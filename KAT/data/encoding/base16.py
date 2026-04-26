# RFC 4648 §8 — Base 16 Encoding Test Vectors
meta = {
    "group": "encoding",
    "algorithm": "base16",
    "source": "rfc",
    "source_ref": "RFC 4648 §8 / KAT/repo/encoding/base16/tests/test001_testvect.c",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # RFC 4648 §10 test vectors
    {"id": "base16-rfc4648-0001", "input_ascii": "",      "output_ascii": ""},
    {"id": "base16-rfc4648-0002", "input_ascii": "f",     "output_ascii": "66"},
    {"id": "base16-rfc4648-0003", "input_ascii": "fo",    "output_ascii": "666F"},
    {"id": "base16-rfc4648-0004", "input_ascii": "foo",   "output_ascii": "666F6F"},
    {"id": "base16-rfc4648-0005", "input_ascii": "foob",  "output_ascii": "666F6F62"},
    {"id": "base16-rfc4648-0006", "input_ascii": "fooba", "output_ascii": "666F6F6261"},
    {"id": "base16-rfc4648-0007", "input_ascii": "foobar","output_ascii": "666F6F626172"},
    # Additional standard vectors
    {"id": "base16-misc-0001", "input_hex": "00",       "output_ascii": "00"},
    {"id": "base16-misc-0002", "input_hex": "ff",       "output_ascii": "FF"},
    {"id": "base16-misc-0003", "input_hex": "deadbeef", "output_ascii": "DEADBEEF"},
    {"id": "base16-misc-0004", "input_hex": "0f1e2d3c", "output_ascii": "0F1E2D3C"},
    {"id": "base16-auto-0012", "input_ascii": "a", "output_ascii": "61"},
    {"id": "base16-auto-0013", "input_ascii": "abc", "output_ascii": "616263"},
    {"id": "base16-auto-0014", "input_ascii": "Hello, World!", "output_ascii": "48656C6C6F2C20576F726C6421"},
    {"id": "base16-auto-0015", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_ascii": "54686520717569636B2062726F776E20666F78206A756D7073206F76657220746865206C617A7920646F67"},
    {"id": "base16-auto-0016", "input_ascii": "0123456789", "output_ascii": "30313233343536373839"},
    {"id": "base16-auto-0017", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_ascii": "6162636465666768696A6B6C6D6E6F707172737475767778797A"},
    {"id": "base16-auto-0018", "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "output_ascii": "4142434445464748494A4B4C4D4E4F505152535455565758595A"},
    {"id": "base16-auto-0019", "input_ascii": "Man", "output_ascii": "4D616E"},
    {"id": "base16-auto-0020", "input_ascii": "pleasure.", "output_ascii": "706C6561737572652E"},

]
