# CRC-64 — ECMA-182 (poly 0x42F0E1EBA9EA3693) and Jones variant
meta = {
    "group": "encoding",
    "algorithm": "crc64",
    "source": "ecma",
    "source_ref": "ECMA-182 / Jones variant / KAT/repo/encoding/crc64",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # ECMA-182 polynomial 0x42F0E1EBA9EA3693, init=0, normal (non-reflected)
    {"id": "crc64-ecma182-0001", "input_ascii": "",         "output_hex": "0000000000000000",
     "variant": "ecma182"},
    {"id": "crc64-ecma182-0002", "input_ascii": "123456789", "output_hex": "6c40df5f0b497347",
     "variant": "ecma182"},
    {"id": "crc64-ecma182-0003", "input_ascii": "a",         "output_hex": "3420000000000000",
     "variant": "ecma182"},
    # Jones / ISO 3309 variant — poly 0xad93d23594c935a9, reflected, init=0
    {"id": "crc64-jones-0001", "input_ascii": "",         "output_hex": "0000000000000000",
     "variant": "jones"},
    {"id": "crc64-jones-0002", "input_ascii": "123456789", "output_hex": "e9c6d914c4b8d9ca",
     "variant": "jones"},
    # XZ / Go standard library variant — poly 0xad93d23594c935a9, init=0xffffffffffffffff, XOR=0xffffffffffffffff
    {"id": "crc64-xz-0001", "input_ascii": "",         "output_hex": "0000000000000000",
     "variant": "xz"},
    {"id": "crc64-xz-0002", "input_ascii": "123456789", "output_hex": "995dc9bbdf1939fa",
     "variant": "xz"},
    {"id": "crc64-auto-0008", "input_ascii": "abc", "output_hex": "66501a349a0e0855", "variant": "ecma182"},
    {"id": "crc64-auto-0009", "input_ascii": "message digest", "output_hex": "c04d61278997ba5e", "variant": "ecma182"},
    {"id": "crc64-auto-0010", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "97a2566b552fcc4e", "variant": "ecma182"},
    {"id": "crc64-auto-0011", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "41e05242ffa9883b", "variant": "ecma182"},
    {"id": "crc64-auto-0012", "input_ascii": "Hello, World!", "output_hex": "a6f2204da53a9036", "variant": "ecma182"},
    {"id": "crc64-auto-0013", "input_ascii": "abc", "output_hex": "00c6468600000000", "variant": "jones"},
    {"id": "crc64-auto-0014", "input_ascii": "message digest", "output_hex": "004ba9c795e54369", "variant": "jones"},
    {"id": "crc64-auto-0015", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "007e5e5a6a762625", "variant": "jones"},
    {"id": "crc64-auto-0016", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "006655162f2d77dc", "variant": "jones"},
    {"id": "crc64-auto-0017", "input_ascii": "Hello, World!", "output_hex": "00a8495a2293a204", "variant": "jones"},
    {"id": "crc64-auto-0018", "input_ascii": "abc", "output_hex": "ffc6467900000000", "variant": "xz"},
    {"id": "crc64-auto-0019", "input_ascii": "message digest", "output_hex": "ff4ba9c795e54396", "variant": "xz"},
    {"id": "crc64-auto-0020", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "ff7e5e5a6a892625", "variant": "xz"},

]
