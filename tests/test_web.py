from scry.scanner import run_scan
from scry.web.app import create_app


def test_dashboard_api_and_guards(tmp_path):
    root = tmp_path / "Documents"
    root.mkdir()
    (root / "kyc.txt").write_text("Aadhaar: 2345 6789 0124")
    db = tmp_path / "t.db"
    run_scan([root], db, ocr=False)

    c = create_app(db).test_client()
    assert c.get("/", base_url="http://127.0.0.1").status_code == 200
    s = c.get("/api/summary", base_url="http://localhost").get_json()
    assert s["files"] == 1

    # DNS-rebinding style request from another host is rejected
    assert c.get("/api/summary", base_url="http://attacker.example").status_code == 403
    # state-changing calls need the per-session token
    assert c.post("/api/scan", json={"paths": [str(root)]}, base_url="http://127.0.0.1").status_code == 403

    files = c.get("/api/files", base_url="http://127.0.0.1").get_json()
    detail = c.get(f"/api/file/{files[0]['id']}", base_url="http://127.0.0.1").get_json()
    assert detail["findings"][0]["masked"].endswith("0124")
    assert "2345" not in str(detail)
