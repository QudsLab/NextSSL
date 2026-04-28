# Hex encoding — lowercase hex digit representation of bytes
meta = {
    "group": "encoding",
    "algorithm": "hex",
    "source": "rfc",
    "source_ref": "RFC 4648 §8 (Base16) / KAT/repo/encoding/hex",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # Lowercase hex (canonical in this project)
    {"id": "hex-basic-0001", "input_hex": "",         "output_ascii": ""},
    {"id": "hex-basic-0002", "input_ascii": "f",      "output_ascii": "66"},
    {"id": "hex-basic-0003", "input_ascii": "fo",     "output_ascii": "666f"},
    {"id": "hex-basic-0004", "input_ascii": "foo",    "output_ascii": "666f6f"},
    {"id": "hex-basic-0005", "input_ascii": "foobar", "output_ascii": "666f6f626172"},
    {"id": "hex-basic-0006", "input_hex": "00",       "output_ascii": "00"},
    {"id": "hex-basic-0007", "input_hex": "ff",       "output_ascii": "ff"},
    {"id": "hex-basic-0008", "input_hex": "deadbeef", "output_ascii": "deadbeef"},
    {"id": "hex-basic-0009", "input_hex": "0f1e2d3c", "output_ascii": "0f1e2d3c"},
    {"id": "hex-basic-0010", "input_ascii": "Hello, World!", "output_ascii": "48656c6c6f2c20576f726c6421"},
    {"id": "hex-auto-0011", "input_ascii": "", "output_hex": ""},
    {"id": "hex-auto-0012", "input_ascii": "a", "output_hex": "61"},
    {"id": "hex-auto-0013", "input_ascii": "abc", "output_hex": "616263"},
    {"id": "hex-auto-0014", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_hex": "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"},
    {"id": "hex-auto-0015", "input_ascii": "0123456789", "output_hex": "30313233343536373839"},
    {"id": "hex-auto-0016", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_hex": "6162636465666768696a6b6c6d6e6f707172737475767778797a"},
    {"id": "hex-auto-0017", "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "output_hex": "4142434445464748494a4b4c4d4e4f505152535455565758595a"},
    {"id": "hex-auto-0018", "input_ascii": "Man", "output_hex": "4d616e"},
    {"id": "hex-auto-0019", "input_ascii": "pleasure.", "output_hex": "706c6561737572652e"},
    {"id": "hex-auto-0020", "input_ascii": "leasure.", "output_hex": "6c6561737572652e"},

]
