import zipfile

from scry import store
from scry.scanner import run_scan


def make_docx(path, text):
    xml = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           f'<w:body><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body></w:document>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", xml)


def test_end_to_end(tmp_path):
    home = tmp_path / "Downloads"
    (home / "ids").mkdir(parents=True)
    (home / "notes.txt").write_text("Grocery list: milk, eggs")
    (home / "ids" / "kyc.txt").write_text("Aadhaar Number: 2345 6789 0124\nPAN: ABCPE1234F")
    (home / "ids" / "kyc copy.txt").write_text("Aadhaar Number: 2345 6789 0124\nPAN: ABCPE1234F")
    make_docx(home / "payslip.docx", "Payslip March  Net Pay 1,00,000  Account No: 123456789012")
    (home / "node_modules").mkdir()
    (home / "node_modules" / "x.txt").write_text("PAN: ABCPE1234F")  # must be skipped
    db = tmp_path / "t.db"

    run_scan([home], db, ocr=False)
    con = store.connect(db)
    s = store.summary(con)
    assert s["files"] == 4
    types = {r["info_type"]: r for r in s["by_info_type"]}
    assert types["aadhaar"]["files"] == 2 and types["aadhaar"]["uniq"] == 1
    assert s["duplicates"]["extra"] == 1

    files = {f["name"]: f for f in store.list_files(con)}
    assert files["kyc.txt"]["label"] == "Highly Confidential"
    assert files["notes.txt"]["label"] == "General"
    assert files["payslip.docx"]["doc_type"] == "Salary slip"
    assert files["kyc.txt"]["risk"] > files["notes.txt"]["risk"]

    # raw values never stored
    raw = db.read_bytes()
    assert b"2345 6789 0124" not in raw and b"234567890124" not in raw and b"ABCPE1234F" not in raw

    # incremental: delete a file, rescan, it disappears
    (home / "notes.txt").unlink()
    run_scan([home], db, ocr=False)
    con = store.connect(db)
    assert store.summary(con)["files"] == 3
