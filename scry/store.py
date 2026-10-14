"""SQLite storage. Holds metadata, masked previews and salted fingerprints only —
never raw sensitive values or file contents."""
from __future__ import annotations

import json
import os
import secrets
import sqlite3
from pathlib import Path

DEFAULT_DB = Path(os.environ.get("SCRY_DB", Path.home() / ".scry" / "scry.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY, started REAL, finished REAL, roots TEXT,
  files INTEGER DEFAULT 0, status TEXT
);
CREATE TABLE IF NOT EXISTS files (
  id INTEGER PRIMARY KEY,
  path TEXT UNIQUE, name TEXT, ext TEXT, folder TEXT, root TEXT,
  size INTEGER, mtime REAL, sha256 TEXT,
  doc_type TEXT, label TEXT, level INTEGER, method TEXT,
  risk INTEGER DEFAULT 0, flags TEXT DEFAULT '[]', dup_count INTEGER DEFAULT 0,
  scanned_at REAL, scan_id INTEGER
);
CREATE TABLE IF NOT EXISTS findings (
  file_id INTEGER REFERENCES files(id) ON DELETE CASCADE,
  info_type TEXT, masked TEXT, fp TEXT, confidence TEXT
);
CREATE INDEX IF NOT EXISTS ix_find_file ON findings(file_id);
CREATE INDEX IF NOT EXISTS ix_find_type ON findings(info_type);
CREATE INDEX IF NOT EXISTS ix_files_sha ON files(sha256);
"""


def connect(db_path: Path | str = DEFAULT_DB) -> sqlite3.Connection:
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(db_path.parent, 0o700)
    except OSError:
        pass
    con = sqlite3.connect(db_path, check_same_thread=False, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(SCHEMA)
    try:
        os.chmod(db_path, 0o600)
    except OSError:
        pass
    return con


def get_salt(con: sqlite3.Connection) -> str:
    row = con.execute("SELECT value FROM meta WHERE key='salt'").fetchone()
    if row:
        return row["value"]
    salt = secrets.token_hex(16)
    con.execute("INSERT INTO meta(key,value) VALUES('salt',?)", (salt,))
    con.commit()
    return salt


def rows(con, sql, args=()):
    return [dict(r) for r in con.execute(sql, args).fetchall()]


# ---------------------------------------------------------------- queries
def summary(con) -> dict:
    tot = con.execute("SELECT COUNT(*) n, COALESCE(SUM(size),0) b FROM files").fetchone()
    by_label = rows(con, "SELECT label, COUNT(*) n, SUM(size) b FROM files GROUP BY label")
    by_type = rows(con, """
        SELECT f.info_type, COUNT(DISTINCT f.file_id) files, COUNT(DISTINCT f.fp) uniq
        FROM findings f GROUP BY f.info_type ORDER BY files DESC""")
    by_doc = rows(con, "SELECT doc_type, COUNT(*) n, MAX(level) level FROM files GROUP BY doc_type ORDER BY n DESC")
    by_folder = rows(con, """
        SELECT folder, COUNT(*) n, SUM(CASE WHEN level>=3 THEN 1 ELSE 0 END) sensitive, MAX(risk) max_risk
        FROM files GROUP BY folder ORDER BY sensitive DESC, n DESC LIMIT 25""")
    needs_ocr = con.execute("SELECT COUNT(*) FROM files WHERE method='needs_ocr'").fetchone()[0]
    dup = con.execute("""SELECT COUNT(*) groups, COALESCE(SUM(c-1),0) extra, COALESCE(SUM((c-1)*s),0) wasted FROM
                          (SELECT sha256, COUNT(*) c, MAX(size) s FROM files WHERE sha256 IS NOT NULL
                           GROUP BY sha256 HAVING c>1)""").fetchone()
    flags = {}
    for r in con.execute("SELECT flags FROM files WHERE level>=3"):
        for fl in json.loads(r["flags"] or "[]"):
            flags[fl] = flags.get(fl, 0) + 1
    last = con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    return {
        "files": tot["n"], "bytes": tot["b"], "by_label": by_label, "by_info_type": by_type,
        "by_doc_type": by_doc, "by_folder": by_folder, "needs_ocr": needs_ocr,
        "duplicates": dict(dup), "sensitive_exposure": flags,
        "last_scan": dict(last) if last else None,
    }


def list_files(con, q="", label="", info_type="", doc_type="", sort="risk", limit=500):
    where, args = ["1=1"], []
    if q:
        where.append("(f.path LIKE ? OR f.doc_type LIKE ?)")
        args += [f"%{q}%", f"%{q}%"]
    if label:
        where.append("f.label=?"); args.append(label)
    if doc_type:
        where.append("f.doc_type=?"); args.append(doc_type)
    if info_type:
        where.append("EXISTS (SELECT 1 FROM findings x WHERE x.file_id=f.id AND x.info_type=?)")
        args.append(info_type)
    order = {"risk": "f.risk DESC, f.level DESC", "size": "f.size DESC", "name": "f.name",
             "modified": "f.mtime DESC"}.get(sort, "f.risk DESC")
    sql = f"""SELECT f.*, (SELECT GROUP_CONCAT(info_type || ':' || n) FROM
                 (SELECT info_type, COUNT(*) n FROM findings WHERE file_id=f.id GROUP BY info_type)) types
              FROM files f WHERE {' AND '.join(where)} ORDER BY {order} LIMIT ?"""
    out = rows(con, sql, args + [limit])
    for r in out:
        r["flags"] = json.loads(r["flags"] or "[]")
        r["types"] = dict(t.split(":") for t in r["types"].split(",")) if r["types"] else {}
    return out


def file_detail(con, file_id: int):
    f = con.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not f:
        return None
    d = dict(f)
    d["flags"] = json.loads(d["flags"] or "[]")
    d["findings"] = rows(con, "SELECT info_type, masked, fp, confidence FROM findings WHERE file_id=? ORDER BY info_type", (file_id,))
    d["duplicates"] = [r["path"] for r in con.execute(
        "SELECT path FROM files WHERE sha256=? AND id<>?", (d["sha256"], file_id))] if d["sha256"] else []
    # where else does the same sensitive value appear?
    d["shared_values"] = rows(con, """
        SELECT x.info_type, x.masked, COUNT(DISTINCT x.file_id) files FROM findings x
        WHERE x.fp IN (SELECT fp FROM findings WHERE file_id=?) AND x.info_type NOT IN ('email','phone','ifsc')
        GROUP BY x.fp HAVING files>1 ORDER BY files DESC LIMIT 20""", (file_id,))
    return d


def duplicate_groups(con, limit=200):
    groups = rows(con, """SELECT sha256, COUNT(*) c, MAX(size) size, MAX(level) level FROM files
                          WHERE sha256 IS NOT NULL GROUP BY sha256 HAVING c>1
                          ORDER BY (c-1)*MAX(size) DESC LIMIT ?""", (limit,))
    for g in groups:
        g["paths"] = [r["path"] for r in con.execute("SELECT path FROM files WHERE sha256=? ORDER BY mtime", (g["sha256"],))]
    return groups
