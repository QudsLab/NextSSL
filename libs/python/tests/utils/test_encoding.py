"""Encoding tests - Base64, Hex, FlexFrame-70."""

from .common import has_binaries, TEST_DATA_EMPTY, TEST_DATA_SHORT, TEST_DATA_BLOCK


def run(log):
    from nextssl.encoding import EncodingType

    # ------------------------------------------------------------------
    log.section("EncodingType enum validation")
    # ------------------------------------------------------------------

    expected = {
        "BASE64": 0, "BASE64_URL": 1, "HEX": 2, "HEX_UPPER": 3, "FLEXFRAME_70": 10,
    }

    for name, val in expected.items():
        member = EncodingType[name]
        log.check(member.value == val, f"EncodingType.{name}", value=member.value, expected=val)

    log.check(len(EncodingType) == len(expected),
              "EncodingType member count", got=len(EncodingType), expected=len(expected))

    # ------------------------------------------------------------------
    # Constructor + functional tests require C binaries
    # ------------------------------------------------------------------

    if not has_binaries():
        log.info("C binaries not available - skipping constructor and functional encoding tests")
        return

    from nextssl.encoding import Base64, Hex, FlexFrame70, b64encode, b64decode, hexencode, hexdecode

    log.section("Hex encode/decode (Python fallback)")

    for label, data in [("empty", TEST_DATA_EMPTY), ("short", TEST_DATA_SHORT), ("block", TEST_DATA_BLOCK)]:
        encoded = Hex().encode(data)
        decoded = Hex().decode(encoded)
        log.check(decoded == data, f"Hex roundtrip ({label})", encoded_len=len(encoded))

    encoded_up = Hex(uppercase=True).encode(b"\xab\xcd\xef")
    log.check(encoded_up == "ABCDEF", "Hex uppercase output", got=encoded_up)

    encoded_low = Hex(uppercase=False).encode(b"\xab\xcd\xef")
    log.check(encoded_low == "abcdef", "Hex lowercase output", got=encoded_low)

    log.section("Hex convenience functions")

    for data in [TEST_DATA_EMPTY, TEST_DATA_SHORT]:
        enc = hexencode(data)
        dec = hexdecode(enc)
        log.check(dec == data, f"hexencode/hexdecode ({len(data)} bytes)")

    log.section("Base64 constructor")

    b64 = Base64(url_safe=False)
    log.check(b64.url_safe is False, "Base64(url_safe=False)")
    b64u = Base64(url_safe=True)
    log.check(b64u.url_safe is True, "Base64(url_safe=True)")

    log.section("FlexFrame70 constructor")

    ff = FlexFrame70()
    log.check(ff is not None, "FlexFrame70 instantiates")

    log.section("Functional: Base64 encode/decode roundtrip")

    for label, data in [("empty", TEST_DATA_EMPTY), ("short", TEST_DATA_SHORT), ("block", TEST_DATA_BLOCK)]:
        encoded = Base64().encode(data)
        decoded = Base64().decode(encoded)
        log.check(decoded == data, f"Base64 roundtrip ({label})")

    log.section("Functional: FlexFrame-70 encode/decode roundtrip")

    ff = FlexFrame70()
    encoded = ff.encode(TEST_DATA_SHORT)
    data, meta = ff.decode(encoded)
    log.check(data == TEST_DATA_SHORT, "FlexFrame-70 data roundtrip")
