"""All numbers below are synthetic test values that pass checksums — none are real."""
from scry.detectors import aadhaar_ok, card_ok, luhn_ok, mask, scan_text, sin_ok, verhoeff_ok

FAKE_AADHAAR = "2345 6789 0124"
FAKE_CARD = "4532 0151 1283 0366"
FAKE_SIN = "130 692 544"


def types(text):
    return {f.info_type for f in scan_text(text, salt="t")}


def test_checksums():
    assert verhoeff_ok("234567890124")
    assert not verhoeff_ok("234567890125")
    assert luhn_ok("4111111111111111")
    assert not card_ok("4111111111111111")  # too few distinct digits
    assert aadhaar_ok(FAKE_AADHAAR)
    assert card_ok(FAKE_CARD)
    assert not card_ok("4444444444444448")  # too repetitive
    assert sin_ok(FAKE_SIN)


def test_aadhaar_needs_keyword():
    # A checksum-valid 12 digit number in a bank statement is NOT an Aadhaar
    assert "aadhaar" not in types(f"UPI ref {FAKE_AADHAAR} credited")
    assert "aadhaar" in types(f"Aadhaar No: {FAKE_AADHAAR}")


def test_card_needs_keyword():
    assert "card" not in types(f"order id {FAKE_CARD}")
    assert "card" in types(f"Visa card number {FAKE_CARD} expiry 12/29")


def test_pan_and_ifsc():
    t = types("PAN: ABCPE1234F  IFSC: HDFC0001234")
    assert {"pan", "ifsc"} <= t


def test_bank_account_label():
    assert "bank_account" in types("Account No: 123456789012")
    assert "bank_account" not in types("Order 123456789012")


def test_aws_key_ignores_base64_blobs():
    blob = "iVBORw0KGgoAAAANSUhEUgAKIAABCDEFGHIJKLMNOP4QRSTUV"
    assert "aws_key" not in types(blob)
    assert "aws_key" in types("aws_access_key_id = AKIAABCDEFGHIJKLMNOP")


def test_secret_assignment():
    assert "generic_secret" in types("password = hunter2hunter2")


def test_sin_and_ssn():
    assert "sin_ca" in types(f"Social Insurance Number {FAKE_SIN}")
    assert "ssn_us" in types("SSN 123-45-6789")
    assert "ssn_us" not in types("ref 123-45-6789")


def test_values_are_masked():
    fs = scan_text(f"Aadhaar {FAKE_AADHAAR}", salt="t")
    a = next(f for f in fs if f.info_type == "aadhaar")
    assert "2345" not in a.masked and a.masked.endswith("0124")
    assert mask("someone@example.com") == "s•••@example.com"


def test_fingerprint_is_salted_and_stable():
    a = scan_text("PAN ABCPE1234F", salt="x")[0].fp
    b = scan_text("PAN abcpe1234f".upper(), salt="x")[0].fp
    c = scan_text("PAN ABCPE1234F", salt="y")[0].fp
    assert a == b and a != c
