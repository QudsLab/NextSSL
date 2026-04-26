# RFC 4648 §4 — Base 64 Encoding Test Vectors
meta = {
    "group": "encoding",
    "algorithm": "base64",
    "source": "rfc",
    "source_ref": "RFC 4648 §10 / KAT/repo/encoding/base64/tests/test001_testvect.c",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # RFC 4648 §10 canonical test vectors
    {"id": "base64-rfc4648-0001", "input_ascii": "",       "output_ascii": ""},
    {"id": "base64-rfc4648-0002", "input_ascii": "f",      "output_ascii": "Zg=="},
    {"id": "base64-rfc4648-0003", "input_ascii": "fo",     "output_ascii": "Zm8="},
    {"id": "base64-rfc4648-0004", "input_ascii": "foo",    "output_ascii": "Zm9v"},
    {"id": "base64-rfc4648-0005", "input_ascii": "foob",   "output_ascii": "Zm9vYg=="},
    {"id": "base64-rfc4648-0006", "input_ascii": "fooba",  "output_ascii": "Zm9vYmE="},
    {"id": "base64-rfc4648-0007", "input_ascii": "foobar", "output_ascii": "Zm9vYmFy"},
    # Additional well-known vectors
    {"id": "base64-misc-0001", "input_ascii": "Man",          "output_ascii": "TWFu"},
    {"id": "base64-misc-0002", "input_ascii": "Hello, World!", "output_ascii": "SGVsbG8sIFdvcmxkIQ=="},
    {"id": "base64-misc-0003", "input_hex": "000000",        "output_ascii": "AAAA"},
    {"id": "base64-misc-0004", "input_hex": "ffffff",        "output_ascii": "\/\/\/"},
    # RFC 4648 §9 linebreak decode (line-wrapped input)
    {
        "id": "base64-linebreak-0001",
        "input_ascii": "This is just a simple test\r\nwith multiple lines encoded\r\nin our base64 representation.\r\nThis should also be encoded in a\r\nway that includes linebreaks\r\nin the base64 output",
        "output_ascii": "VGhpcyBpcyBqdXN0IGEgc2ltcGxlIHRlc3QNCndpdGggbXVsdGlwbGUgbGluZXMgZW5jb2RlZA0KaW4gb3VyIGJhc2U2NCByZXByZXNlbnRhdGlvbi4NClRoaXMgc2hvdWxkIGFsc28gYmUgZW5jb2RlZCBpbiBhDQp3YXkgdGhhdCBpbmNsdWRlcyBsaW5lYnJlYWtzDQppbiB0aGUgYmFzZTY0IG91dHB1dA==",
    },
    {"id": "base64-auto-0013", "input_ascii": "a", "output_ascii": "YQ=="},
    {"id": "base64-auto-0014", "input_ascii": "abc", "output_ascii": "YWJj"},
    {"id": "base64-auto-0015", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_ascii": "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZw=="},
    {"id": "base64-auto-0016", "input_ascii": "0123456789", "output_ascii": "MDEyMzQ1Njc4OQ=="},
    {"id": "base64-auto-0017", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_ascii": "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo="},
    {"id": "base64-auto-0018", "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "output_ascii": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="},
    {"id": "base64-auto-0019", "input_ascii": "pleasure.", "output_ascii": "cGxlYXN1cmUu"},
    {"id": "base64-auto-0020", "input_ascii": "leasure.", "output_ascii": "bGVhc3VyZS4="},

]
