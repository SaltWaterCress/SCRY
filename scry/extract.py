"""Turn files into plain text. Everything happens locally.

Supported: PDF, DOCX, XLSX, PPTX, CSV/TXT/MD/JSON/code, EML, HTML.
Optional OCR (images and scanned PDFs) when Tesseract is installed.
"""
from __future__ import annotations

import email
import email.policy
import html
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

MAX_CHARS = 2_000_000
PDF_MAX_PAGES = 15

TEXT_EXT = {"txt", "md", "csv", "tsv", "json", "xml", "yaml", "yml", "ini", "cfg", "conf",
            "env", "log", "py", "js", "ts", "sh", "ps1", "sql", "java", "go", "rb", "pem", "key"}
HTML_EXT = {"html", "htm"}
IMAGE_EXT = {"png", "jpg", "jpeg", "tif", "tiff", "bmp", "heic", "webp"}
OFFICE_EXT = {"docx", "xlsx", "pptx"}
SUPPORTED = TEXT_EXT | HTML_EXT | IMAGE_EXT | OFFICE_EXT | {"pdf", "eml", "xls"}

_TAG = re.compile(r"<[^>]+>")
_DATA_URI = re.compile(r"data:[\w/+.-]+;base64,[A-Za-z0-9+/=\s]+")


def ocr_available() -> bool:
    if not shutil.which("tesseract"):
        return False
    try:
        import pytesseract  # noqa: F401
        from PIL import Image  # noqa: F401
        return True
    except ImportError:
        return False


def _read_text(p: Path) -> str:
    with open(p, "rb") as f:
        return f.read(MAX_CHARS).decode("utf-8", "ignore")


def _strip_html(s: str) -> str:
    s = _DATA_URI.sub(" ", s)  # embedded images are noise (and cause false positives)
    s = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", s)
    return html.unescape(_TAG.sub(" ", s))


def _xml_text(z: zipfile.ZipFile, names) -> str:
    parts = []
    for n in names:
        try:
            parts.append(_TAG.sub(" ", z.read(n).decode("utf-8", "ignore")))
        except KeyError:
            pass
    return html.unescape(" ".join(parts))


def _docx(p: Path) -> str:
    with zipfile.ZipFile(p) as z:
        names = [n for n in z.namelist()
                 if n.startswith("word/") and re.search(r"(document|header\d*|footer\d*|footnotes)\.xml$", n)]
        return _xml_text(z, names)


def _xlsx(p: Path) -> str:
    with zipfile.ZipFile(p) as z:
        names = [n for n in z.namelist()
                 if n == "xl/sharedStrings.xml" or n.startswith("xl/worksheets/sheet")]
        txt = _xml_text(z, names)
    return txt[:MAX_CHARS]


def _pptx(p: Path) -> str:
    with zipfile.ZipFile(p) as z:
        names = sorted(n for n in z.namelist() if re.match(r"ppt/(slides|notesSlides)/\w+\d+\.xml$", n))
        return _xml_text(z, names)


def _pdf(p: Path) -> str:
    if shutil.which("pdftotext"):  # poppler: fast and accurate
        r = subprocess.run(["pdftotext", "-l", str(PDF_MAX_PAGES), "-q", str(p), "-"],
                           capture_output=True, timeout=60)
        return r.stdout.decode("utf-8", "ignore")
    from pypdf import PdfReader
    reader = PdfReader(str(p))
    if reader.is_encrypted:
        try:
            reader.decrypt("")
        except Exception:
            raise ValueError("encrypted")
    return "\n".join((pg.extract_text() or "") for pg in reader.pages[:PDF_MAX_PAGES])


def _eml(p: Path) -> str:
    with open(p, "rb") as f:
        msg = email.message_from_binary_file(f, policy=email.policy.default)
    parts = [f"From: {msg.get('from', '')}\nTo: {msg.get('to', '')}\nSubject: {msg.get('subject', '')}"]
    for part in msg.walk():
        ctype = part.get_content_type()
        if ctype in ("text/plain", "text/html"):
            try:
                body = part.get_content()
            except Exception:
                continue
            parts.append(_strip_html(body) if ctype == "text/html" else body)
    return "\n".join(parts)[:MAX_CHARS]


def _ocr_image(p: Path) -> str:
    import pytesseract
    from PIL import Image
    if p.suffix.lower() == ".heic":
        try:
            import pillow_heif  # type: ignore
            pillow_heif.register_heif_opener()
        except ImportError:
            return ""
    with Image.open(p) as im:
        im = im.convert("L")
        if max(im.size) > 3000:
            im.thumbnail((3000, 3000))
        return pytesseract.image_to_string(im)


def _ocr_pdf(p: Path, pages: int = 3) -> str:
    if not shutil.which("pdftoppm"):
        return ""
    import pytesseract
    from PIL import Image
    out = []
    with tempfile.TemporaryDirectory() as td:
        subprocess.run(["pdftoppm", "-r", "200", "-l", str(pages), "-png", str(p), f"{td}/pg"],
                       capture_output=True, timeout=120)
        for img in sorted(Path(td).glob("pg*.png")):
            with Image.open(img) as im:
                out.append(pytesseract.image_to_string(im.convert("L")))
    return "\n".join(out)


def extract(p: Path, ocr: bool = False) -> tuple[str, str]:
    """Return (text, method). method describes how text was obtained or why not."""
    ext = p.suffix.lower().lstrip(".")
    try:
        if ext == "pdf":
            t = _pdf(p)
            if len(t.strip()) < 40:
                if ocr:
                    return _ocr_pdf(p), "ocr"
                return t, "needs_ocr"
            return t, "pdf"
        if ext == "docx":
            return _docx(p), "docx"
        if ext == "xlsx":
            return _xlsx(p), "xlsx"
        if ext == "pptx":
            return _pptx(p), "pptx"
        if ext == "eml":
            return _eml(p), "eml"
        if ext in HTML_EXT:
            return _strip_html(_read_text(p)), "html"
        if ext in TEXT_EXT or ext == "xls":
            return _read_text(p), "text"
        if ext in IMAGE_EXT:
            if ocr:
                return _ocr_image(p), "ocr"
            return "", "needs_ocr"
    except zipfile.BadZipFile:
        return "", "error:corrupt"
    except subprocess.TimeoutExpired:
        return "", "error:timeout"
    except ValueError as e:
        return "", f"error:{e}"
    except Exception as e:  # never let one bad file kill the scan
        return "", f"error:{type(e).__name__}"
    return "", "unsupported"
