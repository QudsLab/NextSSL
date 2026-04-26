# RFC 4648 §5 — Base 64 URL-safe Encoding Test Vectors
meta = {
    "group": "encoding",
    "algorithm": "base64url",
    "source": "rfc",
    "source_ref": "RFC 4648 §5 / KAT/repo/encoding/base64url",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # RFC 4648 §10 — same vectors as base64 but '+' → '-' and '/' → '_'
    {"id": "base64url-rfc4648-0001", "input_ascii": "",       "output_ascii": ""},
    {"id": "base64url-rfc4648-0002", "input_ascii": "f",      "output_ascii": "Zg=="},
    {"id": "base64url-rfc4648-0003", "input_ascii": "fo",     "output_ascii": "Zm8="},
    {"id": "base64url-rfc4648-0004", "input_ascii": "foo",    "output_ascii": "Zm9v"},
    {"id": "base64url-rfc4648-0005", "input_ascii": "foob",   "output_ascii": "Zm9vYg=="},
    {"id": "base64url-rfc4648-0006", "input_ascii": "fooba",  "output_ascii": "Zm9vYmE="},
    {"id": "base64url-rfc4648-0007", "input_ascii": "foobar", "output_ascii": "Zm9vYmFy"},
    # URL-safe alphabet difference: bytes that produce '+' or '/' in std base64
    {"id": "base64url-urlsafe-0001",
     "input_hex": "fb",
     "output_ascii": "-w==",
     "note": "0xfb → '+w==' in std, '-w==' in base64url"},
    {"id": "base64url-urlsafe-0002",
     "input_hex": "ff",
     "output_ascii": "_w==",
     "note": "0xff → '/w==' in std, '_w==' in base64url"},
    # No-padding variant (RFC 7515 JWS/JWT style)
    {"id": "base64url-nopad-0001", "input_ascii": "Hello 😃",
     "output_ascii": "SGVsbG8g8J-Ygw",
     "note": "UTF-8 bytes, no trailing '=' padding"},
    {"id": "base64url-auto-0011", "input_ascii": "a", "output_ascii": "YQ=="},
    {"id": "base64url-auto-0012", "input_ascii": "abc", "output_ascii": "YWJj"},
    {"id": "base64url-auto-0013", "input_ascii": "Hello, World!", "output_ascii": "SGVsbG8sIFdvcmxkIQ=="},
    {"id": "base64url-auto-0014", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_ascii": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="},
    {"id": "base64url-auto-0015", "input_ascii": "0123456789", "output_ascii": "MDEyMzQ1Njc4OQ=="},
    {"id": "base64url-auto-0016", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_ascii": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="},
    {"id": "base64url-auto-0017", "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "output_ascii": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="},
    {"id": "base64url-auto-0018", "input_ascii": "Man", "output_ascii": "TWFu"},
    {"id": "base64url-auto-0019", "input_ascii": "pleasure.", "output_ascii": "cGxlYXN1cmUu"},
    {"id": "base64url-auto-0020", "input_ascii": "leasure.", "output_ascii": "bGVhc3VyZS4="},

]
