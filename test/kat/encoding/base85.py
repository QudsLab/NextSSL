# Base85 — multiple variants: ASCII85 (RFC 1924 style), btoa, Z85
meta = {
    "group": "encoding",
    "algorithm": "base85",
    "source": "rfc",
    "source_ref": "RFC 1924 / ZeroMQ Z85 / KAT/repo/encoding/base85/tests/data.js",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # --- ASCII85 (Ascii 85 / Adobe PostScript, with <~ ~> delimiters) ---
    {"id": "base85-ascii85-0001", "variant": "ascii85", "input_ascii": "",                "output_ascii": "<~~>"},
    {"id": "base85-ascii85-0002", "variant": "ascii85", "input_ascii": "Man ",            "output_ascii": "<~9jqo^~>"},
    {"id": "base85-ascii85-0003", "variant": "ascii85", "input_ascii": "Man a",           "output_ascii": "<~9jqo^@/~>"},
    {"id": "base85-ascii85-0004", "variant": "ascii85", "input_ascii": "Man ab",          "output_ascii": "<~9jqo^@:B~>"},
    {"id": "base85-ascii85-0005", "variant": "ascii85", "input_ascii": "Man abc",         "output_ascii": "<~9jqo^@:E^~>"},
    {"id": "base85-ascii85-0006", "variant": "ascii85", "input_ascii": "Man abcd",        "output_ascii": "<~9jqo^@:E_W~>"},
    {"id": "base85-ascii85-0007", "variant": "ascii85", "input_ascii": "Hello, world!!!!", "output_ascii": "<~87cURD_*#TDfTZ)+X&!P~>"},
    {"id": "base85-ascii85-0008", "variant": "ascii85", "input_hex": "ff",                "output_ascii": "<~rr~>"},
    {"id": "base85-ascii85-0009", "variant": "ascii85", "input_hex": "ffffffff",          "output_ascii": "<~s8W-!~>"},
    {"id": "base85-ascii85-0010", "variant": "ascii85", "input_hex": "00000000",          "output_ascii": "<~z~>",
     "note": "four zero bytes use 'z' shorthand"},
    {"id": "base85-ascii85-0011", "variant": "ascii85",
     "input_hex": "864fd26fb559f75b",
     "output_ascii": "<~L/669[9<6.~>"},
    # --- Z85 (ZeroMQ, no delimiters, URL-safe-ish alphabet) ---
    {"id": "base85-z85-0001", "variant": "z85", "input_ascii": "",                "output_ascii": ""},
    {"id": "base85-z85-0002", "variant": "z85", "input_ascii": "Man ",            "output_ascii": "o<}]Z"},
    {"id": "base85-z85-0003", "variant": "z85", "input_ascii": "Hello, world!!!!", "output_ascii": "nm=QNz.92Pz/PV8aT50L"},
    {"id": "base85-z85-0004", "variant": "z85", "input_hex": "ffffffff",          "output_ascii": "%nSc0"},
    {"id": "base85-z85-0005", "variant": "z85", "input_hex": "00000000",          "output_ascii": "00000"},
    {"id": "base85-z85-0006", "variant": "z85",
     "input_hex": "864fd26fb559f75b",
     "output_ascii": "HelloWorld"},
    # --- btoa (RFC 1924, no delimiters) ---
    {"id": "base85-btoa-0001", "variant": "btoa", "input_ascii": "Man ",            "output_ascii": "O<`^z"},
    {"id": "base85-btoa-0002", "variant": "btoa", "input_hex": "ffffffff",          "output_ascii": "|NsC0"},
    {"id": "base85-btoa-0003", "variant": "btoa", "input_hex": "00000000",          "output_ascii": "00000"},
    {"id": "base85-btoa-0004", "variant": "btoa",
     "input_hex": "864fd26fb559f75b",
     "output_ascii": "hELLOwORLD"},
]
