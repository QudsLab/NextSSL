# CRC-32 — ISO 3309 / IEEE 802.3 polynomial 0xEDB88320 (reflected)
meta = {
    "group": "encoding",
    "algorithm": "crc32",
    "source": "iso",
    "source_ref": "ISO 3309 / IEEE 802.3 / RFC 3720 §B.4",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # Poly = 0x04C11DB7, reflected = 0xEDB88320, init = 0xFFFFFFFF, XOR out = 0xFFFFFFFF
    {"id": "crc32-ieee-0001", "input_ascii": "",         "output_hex": "00000000"},
    {"id": "crc32-ieee-0002", "input_ascii": "a",        "output_hex": "e8b7be43"},
    {"id": "crc32-ieee-0003", "input_ascii": "abc",      "output_hex": "352441c2"},
    {"id": "crc32-ieee-0004", "input_ascii": "message digest", "output_hex": "20159d7f"},
    {"id": "crc32-ieee-0005", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "4c2750bd"},
    {"id": "crc32-ieee-0006", "input_hex": "00000000",   "output_hex": "2144df1c"},
    {"id": "crc32-ieee-0007", "input_hex": "ffffffff",   "output_hex": "ffffffff"},
    # RFC 3720 §B.4 iSCSI test vector
    {"id": "crc32-iscsi-0001",
     "input_hex": "01c0000000000000000000000000000000000000000000000000000000000000",
     "output_hex": "7b09b063",
     "note": "CRC32c (Castagnoli) — polynomial 0x1EDC6F41 (reflected 0x82F63B78)",
     "variant": "crc32c"},
    # Python zlib.crc32 reference
    {"id": "crc32-zlib-0001", "input_ascii": "123456789", "output_hex": "cbf43926"},
    {"id": "crc32-auto-0010", "input_ascii": "foobar", "output_hex": "9ef61f95"},
    {"id": "crc32-auto-0011", "input_ascii": "Hello, World!", "output_hex": "ec4ac3d0"},
    {"id": "crc32-auto-0012", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "414fa339"},
    {"id": "crc32-auto-0013", "input_ascii": "0123456789", "output_hex": "a684c7c6"},
    {"id": "crc32-auto-0014", "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "output_hex": "abf77822"},
    {"id": "crc32-auto-0015", "input_ascii": "Man", "output_hex": "51efd138"},
    {"id": "crc32-auto-0016", "input_ascii": "pleasure.", "output_hex": "fa723990"},
    {"id": "crc32-auto-0017", "input_ascii": "leasure.", "output_hex": "89fa3182"},
    {"id": "crc32-auto-0018", "input_ascii": "easure.", "output_hex": "f6f08461"},
    {"id": "crc32-auto-0019", "input_ascii": "asure.", "output_hex": "03d099fe"},
    {"id": "crc32-auto-0020", "input_ascii": "sure.", "output_hex": "b79813bf"},

]
