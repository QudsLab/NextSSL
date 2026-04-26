# RFC 4648 §6/7 — Base 32 and Base 32 Hex Test Vectors
meta = {
    "group": "encoding",
    "algorithm": "base32",
    "source": "rfc",
    "source_ref": "RFC 4648 §10 / KAT/repo/encoding/base32/tests/test001_testvect.c",
    "generated_by": None,
    "date": "2026-04-23",
}

cases = [
    # RFC 4648 §10 — standard Base32 alphabet (uppercase + padding)
    {"id": "base32-rfc4648-0001", "input_ascii": "",       "output_ascii": ""},
    {"id": "base32-rfc4648-0002", "input_ascii": "f",      "output_ascii": "MY======"},
    {"id": "base32-rfc4648-0003", "input_ascii": "fo",     "output_ascii": "MZXQ===="},
    {"id": "base32-rfc4648-0004", "input_ascii": "foo",    "output_ascii": "MZXW6==="},
    {"id": "base32-rfc4648-0005", "input_ascii": "foob",   "output_ascii": "MZXW6YQ="},
    {"id": "base32-rfc4648-0006", "input_ascii": "fooba",  "output_ascii": "MZXW6YTB"},
    {"id": "base32-rfc4648-0007", "input_ascii": "foobar", "output_ascii": "MZXW6YTBOI======"},
    # Base32Hex (extended hex alphabet, sort-order preserving)
    {"id": "base32hex-rfc4648-0001", "variant": "base32hex", "input_ascii": "",       "output_ascii": ""},
    {"id": "base32hex-rfc4648-0002", "variant": "base32hex", "input_ascii": "f",      "output_ascii": "CO======"},
    {"id": "base32hex-rfc4648-0003", "variant": "base32hex", "input_ascii": "fo",     "output_ascii": "CPNG===="},
    {"id": "base32hex-rfc4648-0004", "variant": "base32hex", "input_ascii": "foo",    "output_ascii": "CPNMU==="},
    {"id": "base32hex-rfc4648-0005", "variant": "base32hex", "input_ascii": "foob",   "output_ascii": "CPNMUOG="},
    {"id": "base32hex-rfc4648-0006", "variant": "base32hex", "input_ascii": "fooba",  "output_ascii": "CPNMUOJ1"},
    {"id": "base32hex-rfc4648-0007", "variant": "base32hex", "input_ascii": "foobar", "output_ascii": "CPNMUOJ1E8======"},
    {"id": "base32-auto-0015", "input_ascii": "a", "output_ascii": "ME======"},
    {"id": "base32-auto-0016", "input_ascii": "abc", "output_ascii": "MFRGG==="},
    {"id": "base32-auto-0017", "input_ascii": "Hello, World!", "output_ascii": "JBSWY3DPFQQFO33SNRSCC==="},
    {"id": "base32-auto-0018", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_ascii": "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWO==="},
    {"id": "base32-auto-0019", "input_ascii": "0123456789", "output_ascii": "GAYTEMZUGU3DOOBZ"},
    {"id": "base32-auto-0020", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_ascii": "MFRGGZDFMZTWQ2LKNNWG23TPOBYXE43UOV3HO6DZPI======"},

]
