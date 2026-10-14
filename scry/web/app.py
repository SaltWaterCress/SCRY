"""Local dashboard. Binds to 127.0.0.1 only and rejects requests whose Host
header isn't localhost (protects against DNS-rebinding attacks from web pages)."""
from __future__ import annotations

import platform
import secrets
import subprocess
import threading
from pathlib import Path

from flask import Flask, abort, jsonify, render_template, request

from .. import __version__, store
from ..detectors import INFO_TYPES
from ..extract import ocr_available
from ..scanner import Progress, run_scan

ALLOWED_HOSTS = {"127.0.0.1", "localhost"}


def create_app(db_path=store.DEFAULT_DB) -> Flask:
    app = Flask(__name__)
    token = secrets.token_urlsafe(24)
    state = {"progress": Progress(), "thread": None}
    lock = threading.Lock()

    def con():
        return store.connect(db_path)

    @app.before_request
    def guard():
        host = (request.host or "").split(":")[0]
        if host not in ALLOWED_HOSTS:
            abort(403)
        if request.method == "POST" and request.headers.get("X-Token") != token:
            abort(403)

    @app.after_request
    def headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/")
    def index():
        defaults = [str(Path(p).expanduser()) for p in ("~/Documents", "~/Downloads", "~/Desktop")
                    if Path(p).expanduser().exists()]
        info = [{"key": t.key, "name": t.name, "category": t.category, "sensitivity": t.sensitivity,
                 "description": t.description} for t in INFO_TYPES]
        return render_template("index.html", token=token, version=__version__, defaults=defaults,
                               info_types=info, ocr=ocr_available(), home=str(Path.home()))

    @app.get("/api/summary")
    def api_summary():
        return jsonify(store.summary(con()))

    @app.get("/api/files")
    def api_files():
        a = request.args
        return jsonify(store.list_files(con(), q=a.get("q", ""), label=a.get("label", ""),
                                        info_type=a.get("info_type", ""), doc_type=a.get("doc_type", ""),
                                        sort=a.get("sort", "risk"), limit=int(a.get("limit", 500))))

    @app.get("/api/file/<int:fid>")
    def api_file(fid):
        d = store.file_detail(con(), fid)
        return jsonify(d) if d else abort(404)

    @app.get("/api/duplicates")
    def api_dups():
        return jsonify(store.duplicate_groups(con()))

    @app.get("/api/progress")
    def api_progress():
        t = state["thread"]
        return jsonify(state["progress"].as_dict() | {"running": bool(t and t.is_alive())})

    @app.post("/api/scan")
    def api_scan():
        with lock:
            t = state["thread"]
            if t and t.is_alive():
                return jsonify({"error": "scan already running"}), 409
            body = request.get_json(force=True) or {}
            paths = [p for p in body.get("paths", []) if p.strip()]
            bad = [p for p in paths if not Path(p).expanduser().exists()]
            if not paths or bad:
                return jsonify({"error": f"folder not found: {', '.join(bad) or '(none given)'}"}), 400
            prog = Progress()
            state["progress"] = prog

            def work():
                try:
                    run_scan(paths, db_path, ocr=bool(body.get("ocr")) or None, full=bool(body.get("full")),
                             progress=prog)
                except Exception as e:  # surface to UI
                    prog.phase = "error"
                    prog.log.append(f"{type(e).__name__}: {e}")

            state["thread"] = threading.Thread(target=work, daemon=True)
            state["thread"].start()
        return jsonify({"ok": True})

    @app.post("/api/reveal/<int:fid>")
    def api_reveal(fid):
        row = con().execute("SELECT path FROM files WHERE id=?", (fid,)).fetchone()
        if not row or not Path(row["path"]).exists():
            abort(404)
        p = row["path"]
        sysname = platform.system()
        if sysname == "Darwin":
            subprocess.Popen(["open", "-R", p])
        elif sysname == "Windows":
            subprocess.Popen(["explorer", "/select,", p])
        else:
            subprocess.Popen(["xdg-open", str(Path(p).parent)])
        return jsonify({"ok": True})

    return app
