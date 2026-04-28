# Base62 — alphanumeric only (0-9 A-Z a-z), variadic-length encoding
meta = {
    "group": "encoding",
    "algorithm": "base62",
    "source": "impl",
    "source_ref": "KAT/repo/encoding/base62 (jxskiss/base62)",
    "generated_by": None,
    "date": "2026-04-23",
}

# Alphabet: 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz
# NOTE: this implementation is NOT compatible with BigInt-based base62 libs.
# Round-trip is guaranteed; exact encoded strings depend on implementation variant.

cases = [
    # Empty
    {"id": "base62-basic-0001", "input_hex": "",         "output_ascii": ""},
    # Single zero byte
    {"id": "base62-basic-0002", "input_hex": "00",       "output_ascii": "00"},
    # All-0xff
    {"id": "base62-basic-0003", "input_hex": "ff",       "output_ascii": "4f"},
    {"id": "base62-basic-0004", "input_hex": "ffff",     "output_ascii": "MNK"},
    # Human-readable string round-trip
    {"id": "base62-str-0001",
     "input_ascii": "Hello, 世界！",
     "note": "UTF-8 round-trip; exact encoded value is implementation-specific"},
]
