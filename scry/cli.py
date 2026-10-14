"""Command-line interface: `scry scan|report|serve|export|reset`."""
from __future__ import annotations

import argparse
import csv
import sys
import time
from pathlib import Path

from . import __version__, store
from .detectors import INFO_TYPES_BY_KEY
from .extract import ocr_available
from .scanner import Progress, run_scan

DEFAULT_ROOTS = ["~/Documents", "~/Downloads", "~/Desktop"]


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def cmd_scan(a):
    roots = a.paths or [r for r in DEFAULT_ROOTS if Path(r).expanduser().exists()]
    ocr = True if a.ocr else (False if a.no_ocr else None)
    print(f"Scanning: {', '.join(roots)}")
    print(f"OCR: {'on' if (ocr if ocr is not None else ocr_available()) else 'off'}   DB: {a.db}")
    prog = Progress()
    t0 = time.time()

    def tick(_):
        if sys.stdout.isatty():
            print(f"\r  {prog.done}/{prog.total} files", end="", flush=True)

    run_scan(roots, a.db, ocr=ocr, full=a.full, include_hidden=a.hidden, progress=prog, on_file=tick)
    for line in prog.log:
        print("\n" + line)
    print(f"\nDone in {time.time() - t0:.0f}s — {prog.total} files, {prog.errors} unreadable.\n")
    cmd_report(a)


def cmd_report(a):
    con = store.connect(a.db)
    s = store.summary(con)
    print(f"Files indexed: {s['files']}  ({human(s['bytes'])})")
    print("\nSensitivity labels")
    for r in sorted(s["by_label"], key=lambda r: r["label"]):
        print(f"  {r['label']:<22}{r['n']:>6}")
    print("\nSensitive info types               files   unique values")
    for r in s["by_info_type"]:
        name = INFO_TYPES_BY_KEY[r["info_type"]].name if r["info_type"] in INFO_TYPES_BY_KEY else r["info_type"]
        print(f"  {name:<32}{r['files']:>6}{r['uniq']:>14}")
    print("\nDocument types")
    for r in s["by_doc_type"][:15]:
        print(f"  {r['doc_type']:<36}{r['n']:>6}")
    d = s["duplicates"]
    print(f"\nDuplicates: {d['extra']} extra copies in {d['groups']} groups, {human(d['wasted'])} wasted")
    if s["needs_ocr"]:
        print(f"Image-only files not read: {s['needs_ocr']} (install Tesseract and rescan with --ocr)")
    print("\nTop 10 riskiest files")
    for f in store.list_files(con, limit=10):
        print(f"  {f['risk']:>3}  {f['label']:<20} {f['doc_type']:<28} {f['path']}")
    print("\nOpen the dashboard: scry serve")


def cmd_export(a):
    con = store.connect(a.db)
    files = store.list_files(con, limit=1_000_000)
    with open(a.out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["path", "doc_type", "label", "risk", "size", "info_types", "flags"])
        for f in files:
            w.writerow([f["path"], f["doc_type"], f["label"], f["risk"], f["size"],
                        "; ".join(f"{k}={v}" for k, v in f["types"].items()), "; ".join(f["flags"])])
    print(f"Wrote {len(files)} rows to {a.out} (contains file paths — treat it as confidential)")


def cmd_serve(a):
    from .web.app import create_app
    app = create_app(a.db)
    url = f"http://127.0.0.1:{a.port}"
    print(f"SCRY dashboard on {url}  (local only — Ctrl+C to stop)")
    if not a.no_browser:
        import threading
        import webbrowser
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=a.port, debug=False, use_reloader=False)


def cmd_reset(a):
    p = Path(a.db)
    for suffix in ("", "-wal", "-shm"):
        q = Path(str(p) + suffix)
        if q.exists():
            q.unlink()
    print(f"Deleted {p}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="scry", description="Local data security posture scanner for your own laptop.")
    ap.add_argument("--version", action="version", version=__version__)
    ap.add_argument("--db", default=str(store.DEFAULT_DB), help="index database path")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan folders (default: Documents, Downloads, Desktop)")
    s.add_argument("paths", nargs="*")
    s.add_argument("--ocr", action="store_true", help="force OCR for images and scanned PDFs")
    s.add_argument("--no-ocr", action="store_true", help="disable OCR even if available")
    s.add_argument("--full", action="store_true", help="rescan unchanged files too")
    s.add_argument("--hidden", action="store_true", help="include hidden files and folders")
    s.set_defaults(fn=cmd_scan)

    sub.add_parser("report", help="print a summary of the last scan").set_defaults(fn=cmd_report)

    e = sub.add_parser("export", help="export file inventory to CSV")
    e.add_argument("--out", default="scry-report.csv")
    e.set_defaults(fn=cmd_export)

    v = sub.add_parser("serve", help="open the local dashboard")
    v.add_argument("--port", type=int, default=8765)
    v.add_argument("--no-browser", action="store_true")
    v.set_defaults(fn=cmd_serve)

    sub.add_parser("reset", help="delete the index database").set_defaults(fn=cmd_reset)

    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
