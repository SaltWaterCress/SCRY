"""Create a folder of FAKE documents for demos, screenshots and testing.

    python scripts/make_demo_data.py ./demo-data
    scry --db demo.db scan ./demo-data && scry --db demo.db serve

Every identifier generated here is synthetic. Numbers pass checksums so the
detectors fire, but none belong to a real person.
"""
import random
import shutil
import sys
import zipfile
from pathlib import Path

random.seed(7)
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "demo-data")

_VD = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],
       [5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]]
_VP = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],
       [9,4,5,3,1,2,7,6,8,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]]
_INV = [0,4,3,2,1,5,6,7,8,9]


def aadhaar():
    base = str(random.randint(2, 9)) + "".join(str(random.randint(0, 9)) for _ in range(10))
    c = 0
    for i, ch in enumerate(reversed(base)):
        c = _VD[c][_VP[(i + 1) % 8][int(ch)]]
    n = base + str(_INV[c])
    return f"{n[:4]} {n[4:8]} {n[8:]}"


def luhn_complete(base):
    for d in range(10):
        s = base + str(d)
        tot = sum((int(x) * (2 if i % 2 else 1)) - (9 if int(x) * (2 if i % 2 else 1) > 9 else 0)
                  for i, x in enumerate(reversed(s)))
        if tot % 10 == 0:
            return s


def card():
    n = luhn_complete("45" + "".join(str(random.randint(0, 9)) for _ in range(13)))
    return " ".join(n[i:i + 4] for i in range(0, 16, 4))


def pan():
    L = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    return "".join(random.choice(L) for _ in range(3)) + "P" + random.choice(L) + f"{random.randint(1000, 9999)}" + random.choice(L)


def acct():
    return "".join(str(random.randint(0, 9)) for _ in range(12))


NAMES = ["Aarav Mehta", "Diya Sharma", "Kabir Rao", "Meera Iyer"]
BANKS = [("HDFC", "HDFC0001234"), ("ICICI", "ICIC0000456"), ("Axis", "UTIB0000789")]


def pdf(path, lines):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    path.parent.mkdir(parents=True, exist_ok=True)
    c = canvas.Canvas(str(path), pagesize=A4)
    y = 800
    for ln in lines:
        c.drawString(50, y, ln)
        y -= 18
        if y < 60:
            c.showPage(); y = 800
    c.save()


def docx(path, paras):
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(f"<w:p><w:r><w:t xml:space=\"preserve\">{p}</w:t></w:r></w:p>" for p in paras)
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/'
                   f'wordprocessingml/2006/main"><w:body>{body}</w:body></w:document>')


def xlsx(path, rows):
    import openpyxl
    path.parent.mkdir(parents=True, exist_ok=True)
    wb = openpyxl.Workbook(); ws = wb.active
    for r in rows:
        ws.append(r)
    wb.save(path)


def main():
    if OUT.exists():
        shutil.rmtree(OUT)
    D, DL, DT = OUT / "Documents", OUT / "Downloads", OUT / "Desktop"
    me, my_pan, my_aad = NAMES[0], pan(), aadhaar()

    # identity
    pdf(DL / "KYC" / "Aadhaar_Aarav.pdf", ["Unique Identification Authority of India", f"Name: {me}",
        "DOB: 14/02/1992", f"Aadhaar No: {my_aad}"])
    pdf(DL / "KYC" / "PAN card scan.pdf", ["INCOME TAX DEPARTMENT  Permanent Account Number", f"{me}", f"PAN: {my_pan}"])
    pdf(DL / "passport_copy.pdf", ["REPUBLIC OF INDIA  PASSPORT", f"Passport No: K{random.randint(1000000, 9999999)}",
        f"Surname: {me.split()[1]}", "Date of Birth: 14/02/1992", "Place of Issue: BENGALURU"])
    DT.mkdir(parents=True, exist_ok=True)
    shutil.copy(DL / "KYC" / "Aadhaar_Aarav.pdf", DT / "aadhaar copy.pdf")

    # salary + tax
    for m in ["Jan", "Feb", "Mar", "Apr", "May", "Jun"]:
        pdf(D / "Salary" / f"Payslip_{m}_2026.pdf", [f"Payslip for {m} 2026", f"Employee: {me}", f"PAN: {my_pan}",
            f"Bank Account No: {acct()}", "Basic Salary 1,20,000", "Gross Earnings 2,10,000", "Net Pay 1,64,500"])
    pdf(D / "Tax" / "Form16_FY2025-26.pdf", ["FORM NO. 16", "Certificate under section 203 of the Income-tax Act",
        f"PAN of employee: {my_pan}", "PAN of deductor: AAACX1234K", "Gross Salary 25,20,000"])
    pdf(D / "Tax" / "ITR-V_AY2026-27.pdf", ["INDIAN INCOME TAX RETURN ACKNOWLEDGEMENT", "Assessment Year 2026-27",
        f"PAN {my_pan}", f"Aadhaar Number {my_aad}"])

    # bank statements (with duplicates)
    for bank, ifsc in BANKS:
        a = acct()
        lines = [f"{bank} Bank Statement of Account", f"Account No: {a}", f"IFSC: {ifsc}", "Opening Balance 4,10,220.00"]
        for _ in range(25):
            lines.append(f"0{random.randint(1, 9)}/0{random.randint(1, 9)}/2026  UPI/{random.randint(10**11, 10**12 - 1)}  "
                         f"{random.randint(100, 90000)}.00")
        lines.append("Closing Balance 5,02,118.40")
        pdf(DL / "Statements" / f"{bank}_FY25-26.pdf", lines)
    shutil.copy(DL / "Statements" / "HDFC_FY25-26.pdf", DL / "HDFC_FY25-26 (1).pdf")
    shutil.copy(DL / "Statements" / "HDFC_FY25-26.pdf", DL / "HDFC_FY25-26 (2).pdf")

    # card + wire
    pdf(DL / "credit_card_statement_sep.pdf", ["Credit Card Statement", f"Visa Card Number {card()}",
        "Payment due 05/10/2026", "Total due 48,120.00"])
    pdf(DL / "Wire" / "swift_confirmation.pdf", ["SWIFT MT103 confirmation", "Beneficiary bank SWIFT: CHASUS33XXX",
        f"Ordering customer {me}", "Amount USD 40,000.00"])

    # hr / legal
    docx(D / "Career" / "Offer Letter - Northwind.docx", ["We are pleased to offer you the position of Senior Manager.",
        "Your annual Cost to Company (CTC) will be INR 42,00,000.", f"Contact: {me.split()[0].lower()}@example.com, +91 98765 43210"])
    docx(D / "Career" / "Resume_Aarav.docx", [me, "Professional Summary", "Work Experience", "Education",
        f"{me.split()[0].lower()}.{me.split()[1].lower()}@example.com  +91 91234 56789"])
    pdf(D / "Legal" / "Rental Agreement.pdf", ["RENTAL AGREEMENT", "This Agreement is made between ...",
        f"Tenant: {me}, PAN {my_pan}", "IN WITNESS WHEREOF the parties have signed"])

    # family
    for n in NAMES[1:]:
        pdf(DL / "Family KYC" / f"{n.split()[0]}_aadhaar.pdf", ["Unique Identification Authority of India",
            f"Name: {n}", f"Aadhaar: {aadhaar()}"])

    # secrets and data exports
    (D / "Projects" / "scripts").mkdir(parents=True, exist_ok=True)
    (D / "Projects" / "scripts" / "deploy.sh").write_text(
        "#!/bin/sh\nexport AWS_ACCESS_KEY_ID=AKIAEXAMPLE7DEMOKEY1\nexport DB_PASSWORD=Sup3rSecret!2026\n")
    (D / "Projects" / "notes.md").write_text("# Notes\nwifi password: LongWeekend#42\n")
    xlsx(D / "Finance" / "Investments.xlsx", [["Fund", "Folio", "Units"], ["Index Fund", "1234567/89", 512.3],
        ["PAN", my_pan, ""]])
    xlsx(DL / "contacts_export.xlsx", [["Name", "Email", "Phone"]] +
         [[n, f"{n.split()[0].lower()}@example.com", f"+91 9{random.randint(100000000, 999999999)}"] for n in NAMES])

    # boring stuff
    (D / "Recipes").mkdir(parents=True, exist_ok=True)
    (D / "Recipes" / "dal.txt").write_text("Toor dal, turmeric, ghee, cumin. Pressure cook 3 whistles.")
    pdf(DL / "Trip" / "Goa_itinerary.pdf", ["E-Ticket  PNR: QX7Z2M", "Departure 07:15 BLR → GOI"])
    docx(D / "Ideas.docx", ["Weekend project: build a personal DSPM scanner."])
    print(f"Demo data written to {OUT.resolve()}")


if __name__ == "__main__":
    main()
