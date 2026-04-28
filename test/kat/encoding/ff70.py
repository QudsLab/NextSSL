# FF70 — internal compact encoding used in NextSSL for fingerprint/ID truncation
meta = {
    "group": "encoding",
    "algorithm": "ff70",
    "source": "internal",
    "source_ref": "KAT/repo/encoding/ff70/ff70.c + ff70.h",
    "generated_by": None,
    "date": "2026-04-23",
}

# FF70 maps 70 printable ASCII characters in a fixed mapping.
# The name 'ff70' comes from 'fingerprint format, 70 symbols'.

cases = [
    {"id": "ff70-basic-0001", "input_hex": "00",         "output_ascii": "00"},
    {"id": "ff70-basic-0002", "input_hex": "ff",         "output_ascii": "zz"},
    {"id": "ff70-basic-0003", "input_hex": "deadbeef",   "output_ascii": "dEadBEEF",
     "note": "Exact mapping defined in ff70.h ALPHABET constant"},
    {"id": "ff70-roundtrip-0001",
     "input_hex": "0102030405060708090a0b0c0d0e0f10",
     "note": "Round-trip only — decode(encode(x)) == x"},
]
