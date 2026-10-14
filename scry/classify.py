"""Document-type classification, sensitivity labels and exposure/risk scoring.

Document type uses simple, explainable rules: file name first, then the
first few thousand characters of content. Rules are ordered; first match wins.
"""
from __future__ import annotations

import os
import re
import stat
import time
from functools import lru_cache
from pathlib import Path

from .detectors import INFO_TYPES_BY_KEY

# (document type, sensitivity 1-4, filename regex, content regex)
DOC_RULES: list[tuple[str, int, str | None, str | None]] = [
    ("Passport", 4, r"passport", r"republic of india.{0,80}passport|passport no|type\s*/\s*country code"),
    ("Aadhaar card", 4, r"a+dha+r|eaadhaar", r"unique identification authority|aadhaar|आधार"),
    ("PAN card", 4, r"\bpan[ _-]?card", r"income tax department.{0,80}permanent account number"),
    ("Driving licence", 4, r"driving|licen[cs]e", r"driving licen[cs]e|transport department"),
    ("Birth / marriage certificate", 4, r"birth|marriage", r"certificate of (birth|marriage)|registrar of births"),
    ("Immigration / visa paperwork", 4, r"uscis|i-?\d{3}[a-z]?\b|visa|eb-?5|g-?1650|i-?526", r"uscis|department of homeland security|petition"),
    ("Tax return / ITR", 4, r"\bitr\b|itr[-_ ]?v|tax return|computation|\bay ?\d{2}", r"income tax return|acknowledgement number|assessment year"),
    ("Form 16 / TDS certificate", 4, r"form ?16|_q[1-4]_\d{4}|tds", r"form no\.? 16|certificate under section 203|tds certificate|form 16a"),
    ("Salary slip", 4, r"pay ?slip|salary slip|salary", r"pay ?slip|net pay|gross earnings|earnings.{0,40}deductions"),
    ("Credit card statement", 4, r"credit ?card", r"credit card statement|card number.{0,60}(payment due|total due)"),
    ("Bank statement", 3, r"statement|optransaction|account ?details|passbook", r"opening balance|closing balance|statement of account|transaction date|withdrawal"),
    ("Wire / SWIFT confirmation", 3, r"swift|wire|remittance", r"swift|mt103|beneficiary"),
    ("Trading / broker report", 3, r"trade ?book|tradebook|ledger|profit ?loss|p&l|contract note", r"tradebook|trade date|isin|realised"),
    ("Offer / appraisal / HR letter", 3, r"offer letter|appraisal|award letter|esop|incentive|increment", r"offer of employment|we are pleased to offer|appraisal|stock option"),
    ("Investment / legal agreement", 3, r"agreement|subscription|\blp\b|nda|contract|sow|affidavit|deed", r"this agreement|hereinafter|in witness whereof|affidavit"),
    ("Insurance policy", 3, r"policy|insurance", r"policy (number|schedule)|sum insured|insured"),
    ("Medical / lab report", 4, r"lab ?report|prescription|diagnos|apollo|medical", r"lab report|reference range|specimen|diagnosis"),
    ("Invoice / receipt", 2, r"invoice|receipt|challan|bill", r"invoice (no|number)|tax invoice|receipt|challan"),
    ("Company / registration document", 2, r"incorporation|gst|certificate|udyam|msme", r"certificate of incorporation|registration certificate|gstin"),
    ("Resume / CV", 2, r"resume|\bcv\b|curriculum", r"experience.{0,400}education|professional summary|work experience"),
    ("Travel ticket / itinerary", 2, r"ticket|boarding|itinerary|flight|trip", r"pnr|boarding pass|e-?ticket|departure"),
    ("Screenshot / photo", 2, r"screenshot|whatsapp image|img_|photo|headshot|^image", None),
    ("Signature image", 4, r"signature|sign\.(png|jpe?g)", None),
    ("Source code / config", 1, r"\.(py|js|ts|sh|ps1|json|ya?ml|cfg|conf|ini|env)$", None),
    ("Spreadsheet / data export", 2, r"\.(csv|xlsx?|tsv)$", None),
    ("Presentation", 1, r"\.pptx?$", None),
]
_COMPILED = [(n, s, re.compile(f, re.I) if f else None, re.compile(c, re.I | re.S) if c else None)
             for n, s, f, c in DOC_RULES]

LABELS = {1: "General", 2: "Confidential", 3: "Confidential", 4: "Highly Confidential"}
LABEL_ORDER = ["Public", "General", "Confidential", "Highly Confidential"]

CLOUD_SYNC_MARKERS = ["/Library/Mobile Documents/", "/Library/CloudStorage/", "/iCloud Drive/",
                      "/Google Drive/", "/OneDrive", "/Dropbox/", "/Box/"]
EXPOSED_FOLDERS = ["/Downloads/", "/Desktop/"]


def classify_document(path: str, text: str) -> tuple[str, int]:
    """Score every rule: filename match = 2 points, content match = 1 point.
    Highest score wins; ties go to the rule listed first (most sensitive)."""
    name = os.path.basename(path)
    alt = re.sub(r"[_\-.]+", " ", name)  # so "credit_card" also matches "credit ?card"
    head = text[:6000] if text else ""
    best, best_score = ("Other", 1), 0
    for n, s, f, c in _COMPILED:
        score = (2 if f is not None and (f.search(name) or f.search(alt)) else 0) + (1 if c is not None and head and c.search(head) else 0)
        if score > best_score:
            best, best_score = (n, s), score
    return best


def sensitivity_label(doc_sensitivity: int, finding_types: set[str]) -> tuple[str, int]:
    level = doc_sensitivity
    for k in finding_types:
        t = INFO_TYPES_BY_KEY.get(k)
        if t:
            level = max(level, t.sensitivity)
    if level <= 1 and not finding_types:
        return "General", 1
    return LABELS[level], level


@lru_cache(maxsize=4096)
def _dirs_traversable(d: str) -> bool:
    """True if every directory from / down to d lets other users in (o+x).
    macOS keeps ~/Documents and ~/Downloads at 700, so files there are safe
    from other local accounts even if the file itself is 644."""
    p = Path(d)
    for q in [p, *p.parents]:
        try:
            if not os.stat(q).st_mode & stat.S_IXOTH:
                return False
        except OSError:
            return False
    return True


def exposure(path: Path, st: os.stat_result) -> list[str]:
    p = str(path).replace("\\", "/")
    flags = []
    if any(m in p for m in CLOUD_SYNC_MARKERS):
        flags.append("cloud-synced")
    if any(m in p for m in EXPOSED_FOLDERS):
        flags.append("in Downloads/Desktop")
    if os.name == "posix" and st.st_mode & stat.S_IROTH and _dirs_traversable(str(path.parent)):
        flags.append("readable by other users")
    age_days = (time.time() - st.st_mtime) / 86400
    if age_days > 730:
        flags.append("stale (>2 years)")
    if path.suffix.lower() in (".zip", ".7z", ".rar") :
        flags.append("archive (contents not scanned)")
    return flags


def risk_score(level: int, n_types: int, flags: list[str], duplicates: int) -> int:
    """0-100, additive so files stay distinguishable at the top of the list.

    sensitivity (5-60) + breadth of info types found (0-10) + exposure (0-30)
    """
    score = {1: 5, 2: 20, 3: 40, 4: 60}[level]
    score += min(10, 2 * n_types)
    if "cloud-synced" in flags:
        score += 10
    if "in Downloads/Desktop" in flags:
        score += 7
    if "readable by other users" in flags:
        score += 6
    if "stale (>2 years)" in flags:
        score += 2
    score += min(duplicates, 3) * 2
    # exposure only matters as much as the data is sensitive
    return int(min(100, round(score if level >= 3 else min(score, 45))))
