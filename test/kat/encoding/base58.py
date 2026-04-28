# Base58 — Bitcoin alphabet (no 0, O, I, l)
meta = {
    "group": "encoding",
    "algorithm": "base58",
    "source": "bitcoin-core",
    "source_ref": "KAT/repo/encoding/base58 / Bitcoin Base58 spec",
    "generated_by": None,
    "date": "2026-04-23",
}

# Alphabet: 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz

cases = [
    # From keis/base58 README and Bitcoin Core tests
    {"id": "base58-basic-0001", "input_ascii": "",            "output_ascii": ""},
    {"id": "base58-basic-0002", "input_ascii": "hello world",  "output_ascii": "StV1DL6CwTryKyV"},
    # Leading zero bytes encode as leading '1' characters
    {"id": "base58-leading-0001", "input_hex": "00",           "output_ascii": "1"},
    {"id": "base58-leading-0002", "input_hex": "0000",         "output_ascii": "11"},
    {"id": "base58-leading-0003", "input_hex": "000102",       "output_ascii": "1Ldp"},
    # Bitcoin example from README
    {"id": "base58-btc-0001",
     "input_ascii": "1QCaxc8hutpdZ62iKZsn1TCG3nh7uPZojq",
     "note": "encode/decode round-trip of Bitcoin address string"},
    # XRP / Ripple alphabet variant
    {"id": "base58-xrp-0001",
     "input_ascii": "hello world",
     "output_ascii": "StVrDLaUATiyKyV",
     "variant": "xrp",
     "note": "XRP_ALPHABET differs at positions i/I"},
    {"id": "base58-auto-0008", "input_ascii": "a", "output_ascii": "2g"},
    {"id": "base58-auto-0009", "input_ascii": "abc", "output_ascii": "ZiCa"},
    {"id": "base58-auto-0010", "input_ascii": "foobar", "output_ascii": "t1Zv2yaZ"},
    {"id": "base58-auto-0011", "input_ascii": "Hello, World!", "output_ascii": "72k1xXWG59fYdzSNoA"},
    {"id": "base58-auto-0012", "input_ascii": "The quick brown fox jumps over the lazy dog", "output_ascii": "7DdiPPYtxLjCD3wA1po2rvZHTDYjkZYiEtazrfiwJcwnKCizhGFhBGHeRdx"},
    {"id": "base58-auto-0013", "input_ascii": "0123456789", "output_ascii": "3i37NcgooY8f1S"},
    {"id": "base58-auto-0014", "input_ascii": "abcdefghijklmnopqrstuvwxyz", "output_ascii": "3yxU3u1igY8WkgtjK92fbJQCd4BZiiT1v25f"},
    {"id": "base58-auto-0015", "input_ascii": "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "output_ascii": "2zuFXTJSTRK6ESktqhM2QDBkCnH1U46CnxaD"},
    {"id": "base58-auto-0016", "input_ascii": "Man", "output_ascii": "SzVj"},
    {"id": "base58-auto-0017", "input_ascii": "pleasure.", "output_ascii": "2RzttocMJihSm"},
    {"id": "base58-auto-0018", "input_ascii": "leasure.", "output_ascii": "K8aUZhGUNaR"},
    {"id": "base58-auto-0019", "input_ascii": "easure.", "output_ascii": "4qq4WqChgZ"},
    {"id": "base58-auto-0020", "input_ascii": "asure.", "output_ascii": "qXcNm9C1"},

]
