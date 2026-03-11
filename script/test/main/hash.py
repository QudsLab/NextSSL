"""script/test/main/hash.py â€” functional tests for hash.dll (Main Tier).

Covers all symbols in _WASM_HASH_EXPORTS using run_hash_kat() and direct
ctypes calls for algorithms with non-standard signatures (Argon2id/i/d).
"""
import ctypes
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../')))
from script.core             import Config, console
from script.test.core.result import Results
from script.test.core.hash_runner import run_hash_kat


def main() -> int:
    config   = Config()
    dll_path = config.get_lib_path('main', 'hash')

    console.print_info(f"Loading: {dll_path}")
    if not os.path.exists(dll_path):
        console.print_fail(f"DLL not found: {dll_path}")
        return 1
    try:
        lib = ctypes.CDLL(dll_path)
    except OSError as e:
        console.print_fail(f"Failed to load: {e}")
        return 1
    console.print_pass("DLL loaded")

    r = Results('test/main/hash')

    # â”€â”€ SHA-2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_hash_kat(lib, 'sha256', b"abc",
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                 32, r)
    run_hash_kat(lib, 'sha512_hash', b"abc",
                 "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                 "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
                 64, r)
    run_hash_kat(lib, 'sha224_hash', b"abc",
                 "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
                 28, r)
    run_hash_kat(lib, 'sha384_hash', b"abc",
                 "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                 "8086072ba1e7cc2358baeca134c825a7",
                 48, r)

    # â”€â”€ BLAKE3 / BLAKE2 â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _test_blake3(lib, b"abc",
                 "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
                 32, r)
    run_hash_kat(lib, 'blake2b_512_hash', b"abc",
                 "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
                 "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
                 64, r)
    run_hash_kat(lib, 'blake2s_256_hash', b"abc",
                 "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
                 32, r)

    # â”€â”€ SHA-3 / Keccak â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_hash_kat(lib, 'sha3_256_hash', b"abc",
                 "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
                 32, r)
    run_hash_kat(lib, 'sha3_512_hash', b"abc",
                 "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e"
                 "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
                 64, r)
    run_hash_kat(lib, 'keccak_256_hash', b"",
                 "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
                 32, r)

    # â”€â”€ SHAKE XOF â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _test_shake(lib, 'shake128_hash', b"abc", 16,
                "5881092dd818bf5cf8a3ddb793fbcba7", r)
    _test_shake(lib, 'shake256_hash', b"abc", 32,
                "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739", r)

    # â”€â”€ Legacy â€” alive â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_hash_kat(lib, 'sha1_hash', b"abc",
                 "a9993e364706816aba3e25717850c26c9cd0d89d",
                 20, r)
    run_hash_kat(lib, 'md5_hash', b"abc",
                 "900150983cd24fb0d6963f7d28e17f72",
                 16, r)

    # â”€â”€ Legacy â€” unsafe â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    run_hash_kat(lib, 'md2_hash', b"abc",
                 "da853b0d3f88d99b30283a69e6ded6bb",
                 16, r)
    run_hash_kat(lib, 'md4_hash', b"abc",
                 "a448017aaf21d8525fc10ae87aa6729d",
                 16, r)

    # â”€â”€ Argon2 (memory-hard â€” non-standard signature) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    _test_argon2(lib, 'argon2id_hash_raw', r)
    _test_argon2(lib, 'argon2i_hash_raw',  r)
    _test_argon2(lib, 'argon2d_hash_raw',  r)

    return r.summary()


def _test_blake3(lib, data: bytes, expected_hex: str, out_len: int, r: Results) -> None:
    fn_init = getattr(lib, 'blake3_hasher_init', None)
    fn_update = getattr(lib, 'blake3_hasher_update', None)
    fn_final = getattr(lib, 'blake3_hasher_finalize', None)
    if fn_init is None or fn_update is None or fn_final is None:
        r.fail("blake3_hasher_*", reason="symbol not found")
        return

    fn_init.argtypes = [ctypes.c_void_p]
    fn_update.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    fn_final.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    fn_init.restype = None
    fn_update.restype = None
    fn_final.restype = None

    hasher = ctypes.create_string_buffer(4096)
    fn_init(ctypes.byref(hasher))
    if data:
        buf = ctypes.create_string_buffer(data, len(data))
        fn_update(ctypes.byref(hasher), buf, len(data))
    out = ctypes.create_string_buffer(out_len)
    fn_final(ctypes.byref(hasher), out, out_len)

    if out.raw.hex() == expected_hex:
        r.ok("blake3 KAT")
    else:
        r.fail("blake3 KAT", reason=f"got {out.raw.hex()[:32]}… expected {expected_hex[:32]}…")


def _test_shake(lib, fn_name: str, data: bytes, out_len: int,
                expected_hex: str, r: Results) -> None:
    """SHAKE XOF: signature is (data, data_len, out, out_len)."""
    fn = getattr(lib, fn_name, None)
    if fn is None:
        r.fail(f"{fn_name}", reason="symbol not found")
        return
    fn.argtypes = [ctypes.c_char_p, ctypes.c_size_t,
                   ctypes.c_char_p, ctypes.c_size_t]
    fn.restype  = None
    out = ctypes.create_string_buffer(out_len)
    fn(data, len(data), out, out_len)
    if out.raw.hex() == expected_hex:
        r.ok(f"{fn_name} XOF KAT")
    else:
        r.fail(f"{fn_name} XOF KAT",
               reason=f"got {out.raw.hex()} expected {expected_hex}")


def _test_argon2(lib, fn_name: str, r: Results) -> None:
    """Argon2 variant: (t, m, p, pwd, pwd_len, salt, salt_len, out, out_len)."""
    fn = getattr(lib, fn_name, None)
    if fn is None:
        r.fail(f"{fn_name}", reason="symbol not found")
        return
    fn.argtypes = [
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
    ]
    fn.restype = ctypes.c_int
    out = ctypes.create_string_buffer(32)
    ret = fn(1, 16, 1, b"pass", 4, b"saltsalt", 8, out, 32)
    if ret == 0 and any(out.raw):
        r.ok(f"{fn_name} (non-zero output)")
    else:
        r.fail(f"{fn_name}", reason=f"ret={ret}")


if __name__ == "__main__":
    sys.exit(main())

