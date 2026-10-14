"""Discover → extract → detect → classify → score → store."""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

from . import store
from .classify import classify_document, exposure, risk_score, sensitivity_label
from .detectors import scan_text
from .extract import SUPPORTED, extract, ocr_available

SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "__pycache__", "venv", ".venv", "env",
             "site-packages", ".cache", ".Trash", ".npm", ".pyenv", ".tox", "Library",
             "Applications", ".idea", ".vscode"}
SKIP_DIR_SUFFIXES = (".app", ".framework", ".bundle", ".photoslibrary", ".xcodeproj")
SKIP_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}
MAX_EXTRACT_BYTES = 150 * 1024 * 1024
MAX_HASH_BYTES = 1024 * 1024 * 1024


@dataclass
class Progress:
    phase: str = "idle"
    total: int = 0
    done: int = 0
    current: str = ""
    errors: int = 0
    started: float = 0.0
    finished: float = 0.0
    log: list = field(default_factory=list)

    def as_dict(self):
        return {k: v for k, v in self.__dict__.items() if k != "log"} | {"log": self.log[-8:]}


def discover(roots: list[Path], include_hidden: bool = False) -> Iterator[Path]:
    for root in roots:
        root = root.expanduser().resolve()
        if root.is_file():
            yield root
            continue
        for dp, dns, fns in os.walk(root, onerror=lambda e: None):
            dns[:] = [d for d in dns
                      if d not in SKIP_DIRS and not d.endswith(SKIP_DIR_SUFFIXES)
                      and (include_hidden or not d.startswith("."))]
            for fn in fns:
                if fn in SKIP_FILES or fn.startswith("~$") or (not include_hidden and fn.startswith(".")):
                    continue
                yield Path(dp) / fn


def sha256_file(p: Path, size: int) -> Optional[str]:
    if size == 0 or size > MAX_HASH_BYTES:
        return None
    h = hashlib.sha256()
    try:
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _root_for(p: Path, roots: list[Path]) -> str:
    for r in roots:
        try:
            p.relative_to(r)
            return str(r)
        except ValueError:
            continue
    return str(p.parent)


def run_scan(roots: list[str | Path], db_path=store.DEFAULT_DB, ocr: Optional[bool] = None,
             full: bool = False, include_hidden: bool = False,
             progress: Optional[Progress] = None,
             on_file: Optional[Callable[[str], None]] = None) -> int:
    prog = progress or Progress()
    roots_p = [Path(r).expanduser().resolve() for r in roots]
    if ocr is None:
        ocr = ocr_available()
    elif ocr and not ocr_available():
        prog.log.append("OCR requested but Tesseract/pytesseract not installed — skipping OCR")
        ocr = False

    con = store.connect(db_path)
    salt = store.get_salt(con)
    cur = con.execute("INSERT INTO scans(started, roots, status) VALUES(?,?,?)",
                      (time.time(), json.dumps([str(r) for r in roots_p]), "running"))
    scan_id = cur.lastrowid
    con.commit()

    prog.phase, prog.started, prog.done, prog.errors = "discovering", time.time(), 0, 0
    paths = list(discover(roots_p, include_hidden))
    prog.total, prog.phase = len(paths), "scanning"
    seen: set[str] = set()

    for p in paths:
        sp = str(p)
        seen.add(sp)
        prog.current = sp
        try:
            st = p.stat()
        except OSError:
            prog.errors += 1
            prog.done += 1
            continue

        existing = con.execute("SELECT id, size, mtime, method FROM files WHERE path=?", (sp,)).fetchone()
        unchanged = (existing and existing["size"] == st.st_size and abs(existing["mtime"] - st.st_mtime) < 1
                     and not (ocr and existing["method"] == "needs_ocr"))
        if unchanged and not full:
            con.execute("UPDATE files SET scan_id=? WHERE id=?", (scan_id, existing["id"]))
            prog.done += 1
            continue

        ext = p.suffix.lower().lstrip(".")
        text, method = "", "skipped"
        if ext in SUPPORTED and st.st_size <= MAX_EXTRACT_BYTES:
            text, method = extract(p, ocr=ocr)
        elif ext in SUPPORTED:
            method = "too_large"
        if method.startswith("error"):
            prog.errors += 1

        findings = scan_text(text, salt) if text else []
        doc_type, doc_level = classify_document(sp, text)
        label, level = sensitivity_label(doc_level, {f.info_type for f in findings})
        flags = exposure(p, st)
        digest = sha256_file(p, st.st_size)

        values = (sp, p.name, ext, str(p.parent), _root_for(p, roots_p), st.st_size, st.st_mtime, digest,
                  doc_type, label, level, method, json.dumps(flags), time.time(), scan_id)
        if existing:
            con.execute("""UPDATE files SET path=?, name=?, ext=?, folder=?, root=?, size=?, mtime=?, sha256=?,
                           doc_type=?, label=?, level=?, method=?, flags=?, scanned_at=?, scan_id=? WHERE id=?""",
                        values + (existing["id"],))
            fid = existing["id"]
            con.execute("DELETE FROM findings WHERE file_id=?", (fid,))
        else:
            fid = con.execute("""INSERT INTO files(path, name, ext, folder, root, size, mtime, sha256, doc_type,
                                 label, level, method, flags, scanned_at, scan_id)
                                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", values).lastrowid
        con.executemany("INSERT INTO findings(file_id, info_type, masked, fp, confidence) VALUES(?,?,?,?,?)",
                        [(fid, f.info_type, f.masked, f.fp, f.confidence) for f in findings])
        del text  # file contents are never persisted
        prog.done += 1
        if on_file:
            on_file(sp)
        if prog.done % 50 == 0:
            con.commit()

    # forget files that were deleted from the scanned roots
    prog.phase = "scoring"
    for r in roots_p:
        for row in con.execute("SELECT id, path FROM files WHERE root=?", (str(r),)).fetchall():
            if row["path"] not in seen:
                con.execute("DELETE FROM files WHERE id=?", (row["id"],))

    _rescore(con)
    con.execute("UPDATE scans SET finished=?, files=?, status='done' WHERE id=?",
                (time.time(), len(paths), scan_id))
    con.commit()
    prog.phase, prog.finished, prog.current = "done", time.time(), ""
    con.close()
    return scan_id


def _rescore(con):
    dup = {r["sha256"]: r["c"] for r in con.execute(
        "SELECT sha256, COUNT(*) c FROM files WHERE sha256 IS NOT NULL GROUP BY sha256 HAVING c>1")}
    counts = {r["file_id"]: r["n"] for r in con.execute(
        "SELECT file_id, COUNT(DISTINCT info_type) n FROM findings GROUP BY file_id")}
    updates = []
    for r in con.execute("SELECT id, sha256, level, flags FROM files"):
        d = dup.get(r["sha256"], 1) - 1 if r["sha256"] else 0
        flags = [f for f in json.loads(r["flags"] or "[]") if not f.startswith("duplicate")]
        if d:
            flags.append(f"duplicate ×{d + 1}")
        updates.append((risk_score(r["level"], counts.get(r["id"], 0), flags, d), json.dumps(flags), d, r["id"]))
    con.executemany("UPDATE files SET risk=?, flags=?, dup_count=? WHERE id=?", updates)
