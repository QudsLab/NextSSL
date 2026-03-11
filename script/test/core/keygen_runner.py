"""script/test/core/keygen_runner.py — one-shot keygen round-trip runner.

run_keygen_oneshotmodes() exercises every requested mode for one algorithm
and verifies correctness, determinism, uniqueness, and non-zero output.
"""
import ctypes
from script.core import console
from .result import Results


def _dbg(debug: bool, label: str, value, hex_dump: bool = False) -> None:
    """Emit a debug key=value entry when debug mode is active."""
    if not debug:
        return
    if hex_dump and isinstance(value, (bytes, bytearray)):
        value = value.hex()
    console.print_debug_val(label, value)


def run_keygen_oneshotmodes(
    lib,
    algo:    str,
    pk_size: int,
    sk_size: int,
    modes:   list,
    results: Results,
    debug:   bool = False,
) -> None:
    """For each mode in *modes*, call keygen_<algo>_<mode>(...) and verify:
      - return value == 0
      - pk and sk buffers are non-zero
      - drbg / password / hd modes produce identical output for identical input
        (determinism check)
      - two calls with different inputs produce different output (uniqueness)

        Function signatures by mode:
            random   : (pk, sk)
            drbg     : (seed, seed_len, label, pk, sk)
            password : (pwd, pwd_len, salt, salt_len, params, pk, sk)
            hd       : (master, master_len, path, pk, sk)
    """
    for mode in modes:
        fn_name = f"keygen_{algo}_{mode}"
        try:
            fn = getattr(lib, fn_name)
        except AttributeError:
            results.fail(f"{fn_name}", reason="symbol not found in binary")
            continue

        pk1 = ctypes.create_string_buffer(pk_size)
        sk1 = ctypes.create_string_buffer(sk_size)

        if mode == 'random':
            fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            fn.restype  = ctypes.c_int

            # Test 1: non-zero output
            ret = fn(pk1, sk1)
            _dbg(debug, f"{fn_name}/random ret1", ret)
            _dbg(debug, f"{fn_name}/random pk1[0:8]", pk1.raw[:8], hex_dump=True)
            if ret == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={ret}",
                             debug_data={"pk": pk1.raw, "sk": sk1.raw} if debug else None)

            # Test 2: uniqueness — two random calls should differ
            pk2 = ctypes.create_string_buffer(pk_size)
            sk2 = ctypes.create_string_buffer(sk_size)
            r2 = fn(pk2, sk2)
            _dbg(debug, f"{fn_name}/random ret2", r2)
            _dbg(debug, f"{fn_name}/random pk2[0:8]", pk2.raw[:8], hex_dump=True)
            if r2 == 0 and pk1.raw != pk2.raw:
                results.ok(f"{fn_name} (random uniqueness)")
            else:
                results.fail(f"{fn_name} (random uniqueness)",
                             reason=f"r2={r2} pk_match={pk1.raw==pk2.raw}",
                             debug_data={"pk1": pk1.raw, "pk2": pk2.raw} if debug else None)

        elif mode == 'drbg':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            fn.restype  = ctypes.c_int
            seed_a = b'\x42' * 32
            seed_b = b'\xAB' * 32
            label  = b"test"
            label2 = b"test2"
            pk2    = ctypes.create_string_buffer(pk_size)
            sk2    = ctypes.create_string_buffer(sk_size)
            pk3    = ctypes.create_string_buffer(pk_size)
            sk3    = ctypes.create_string_buffer(sk_size)
            pk4    = ctypes.create_string_buffer(pk_size)
            sk4    = ctypes.create_string_buffer(sk_size)

            r1 = fn(seed_a, len(seed_a), label, pk1, sk1)
            r2 = fn(seed_a, len(seed_a), label, pk2, sk2)
            _dbg(debug, f"{fn_name}/drbg seed_a", seed_a, hex_dump=True)
            _dbg(debug, f"{fn_name}/drbg r1={r1} r2={r2}", "")
            _dbg(debug, f"{fn_name}/drbg pk1[0:8]", pk1.raw[:8], hex_dump=True)

            # Test 3: non-zero output
            if r1 == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={r1}",
                             debug_data={"pk": pk1.raw, "sk": sk1.raw} if debug else None)

            # Test 4: determinism
            if r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}",
                             debug_data={"pk1": pk1.raw, "pk2": pk2.raw} if debug else None)

            # Test 5: uniqueness — different seed → different keys
            r3 = fn(seed_b, len(seed_b), label, pk3, sk3)
            _dbg(debug, f"{fn_name}/drbg seed_b", seed_b, hex_dump=True)
            _dbg(debug, f"{fn_name}/drbg pk3[0:8]", pk3.raw[:8], hex_dump=True)
            if r3 == 0 and pk1.raw != pk3.raw:
                results.ok(f"{fn_name} (uniqueness — different seed)")
            else:
                results.fail(f"{fn_name} (uniqueness — different seed)",
                             reason=f"r3={r3} pk_match={pk1.raw==pk3.raw}",
                             debug_data={"pk1": pk1.raw, "pk3": pk3.raw} if debug else None)

            # Test 6: uniqueness — different label → different keys
            r4 = fn(seed_a, len(seed_a), label2, pk4, sk4)
            _dbg(debug, f"{fn_name}/drbg label2={label2!r}", "")
            _dbg(debug, f"{fn_name}/drbg pk4[0:8]", pk4.raw[:8], hex_dump=True)
            if r4 == 0 and pk1.raw != pk4.raw:
                results.ok(f"{fn_name} (uniqueness — different label)")
            else:
                results.fail(f"{fn_name} (uniqueness — different label)",
                             reason=f"r4={r4} pk_match={pk1.raw==pk4.raw}",
                             debug_data={"pk1": pk1.raw, "pk4": pk4.raw} if debug else None)

        elif mode == 'password':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_void_p,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            fn.restype  = ctypes.c_int
            pwd   = b"nextssl_test_password"
            pwd2  = b"nextssl_other_password"
            salt  = b"saltsalt12345678"
            pk2   = ctypes.create_string_buffer(pk_size)
            sk2   = ctypes.create_string_buffer(sk_size)
            pk3   = ctypes.create_string_buffer(pk_size)
            sk3   = ctypes.create_string_buffer(sk_size)

            r1 = fn(pwd, len(pwd), salt, len(salt), None, pk1, sk1)
            r2 = fn(pwd, len(pwd), salt, len(salt), None, pk2, sk2)
            _dbg(debug, f"{fn_name}/password r1={r1} r2={r2}", "")
            _dbg(debug, f"{fn_name}/password pk1[0:8]", pk1.raw[:8], hex_dump=True)

            # Test 7: non-zero output
            if r1 == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={r1}",
                             debug_data={"pk": pk1.raw, "sk": sk1.raw} if debug else None)

            # Test 8: determinism
            if r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}",
                             debug_data={"pk1": pk1.raw, "pk2": pk2.raw} if debug else None)

            # Test 9: uniqueness — different password → different keys
            r3 = fn(pwd2, len(pwd2), salt, len(salt), None, pk3, sk3)
            _dbg(debug, f"{fn_name}/password pk3[0:8]", pk3.raw[:8], hex_dump=True)
            if r3 == 0 and pk1.raw != pk3.raw:
                results.ok(f"{fn_name} (uniqueness — different password)")
            else:
                results.fail(f"{fn_name} (uniqueness — different password)",
                             reason=f"r3={r3} pk_match={pk1.raw==pk3.raw}",
                             debug_data={"pk1": pk1.raw, "pk3": pk3.raw} if debug else None)

        elif mode == 'hd':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            fn.restype  = ctypes.c_int
            master  = b'\xBB' * 32
            path1   = b"m/0/0"
            path2   = b"m/0/1"
            pk2     = ctypes.create_string_buffer(pk_size)
            sk2     = ctypes.create_string_buffer(sk_size)
            pk3     = ctypes.create_string_buffer(pk_size)
            sk3     = ctypes.create_string_buffer(sk_size)

            r1 = fn(master, len(master), path1, pk1, sk1)
            r2 = fn(master, len(master), path1, pk2, sk2)
            _dbg(debug, f"{fn_name}/hd r1={r1} r2={r2}", "")
            _dbg(debug, f"{fn_name}/hd pk1[0:8]", pk1.raw[:8], hex_dump=True)

            # Test 10: non-zero output
            if r1 == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={r1}",
                             debug_data={"pk": pk1.raw, "sk": sk1.raw} if debug else None)

            # Test 11: determinism
            if r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}",
                             debug_data={"pk1": pk1.raw, "pk2": pk2.raw} if debug else None)

            # Test 12: uniqueness — different path → different keys
            r3 = fn(master, len(master), path2, pk3, sk3)
            _dbg(debug, f"{fn_name}/hd pk3[0:8]", pk3.raw[:8], hex_dump=True)
            if r3 == 0 and pk1.raw != pk3.raw:
                results.ok(f"{fn_name} (uniqueness — different path)")
            else:
                results.fail(f"{fn_name} (uniqueness — different path)",
                             reason=f"r3={r3} pk_match={pk1.raw==pk3.raw}",
                             debug_data={"pk1": pk1.raw, "pk3": pk3.raw} if debug else None)

        elif mode == 'hash':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            fn.restype  = ctypes.c_int
            seed_a  = b'\x42' * 32
            seed_b  = b'\xAB' * 32
            ctx_a   = b"nextssl-test-ctx"
            ctx_b   = b"nextssl-other-ctx"
            pk2     = ctypes.create_string_buffer(pk_size)
            sk2     = ctypes.create_string_buffer(sk_size)
            pk3     = ctypes.create_string_buffer(pk_size)
            sk3     = ctypes.create_string_buffer(sk_size)
            pk4     = ctypes.create_string_buffer(pk_size)
            sk4     = ctypes.create_string_buffer(sk_size)

            r1 = fn(seed_a, len(seed_a), ctx_a, len(ctx_a), pk1, sk1)
            r2 = fn(seed_a, len(seed_a), ctx_a, len(ctx_a), pk2, sk2)
            _dbg(debug, f"{fn_name}/hash r1={r1} r2={r2}", "")
            _dbg(debug, f"{fn_name}/hash pk1[0:8]", pk1.raw[:8], hex_dump=True)

            # Test 13: non-zero output
            if r1 == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={r1}",
                             debug_data={"pk": pk1.raw, "sk": sk1.raw} if debug else None)

            # Test 14: determinism
            if r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}",
                             debug_data={"pk1": pk1.raw, "pk2": pk2.raw} if debug else None)

            # Test 15: uniqueness — different seed → different keys
            r3 = fn(seed_b, len(seed_b), ctx_a, len(ctx_a), pk3, sk3)
            _dbg(debug, f"{fn_name}/hash pk3[0:8]", pk3.raw[:8], hex_dump=True)
            if r3 == 0 and pk1.raw != pk3.raw:
                results.ok(f"{fn_name} (uniqueness — different seed)")
            else:
                results.fail(f"{fn_name} (uniqueness — different seed)",
                             reason=f"r3={r3} pk_match={pk1.raw==pk3.raw}",
                             debug_data={"pk1": pk1.raw, "pk3": pk3.raw} if debug else None)

            # Test 16: uniqueness — different ctx → different keys
            r4 = fn(seed_a, len(seed_a), ctx_b, len(ctx_b), pk4, sk4)
            _dbg(debug, f"{fn_name}/hash pk4[0:8]", pk4.raw[:8], hex_dump=True)
            if r4 == 0 and pk1.raw != pk4.raw:
                results.ok(f"{fn_name} (uniqueness — different ctx)")
            else:
                results.fail(f"{fn_name} (uniqueness — different ctx)",
                             reason=f"r4={r4} pk_match={pk1.raw==pk4.raw}",
                             debug_data={"pk1": pk1.raw, "pk4": pk4.raw} if debug else None)

        elif mode == 'kdf':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            fn.restype  = ctypes.c_int
            ikm_a   = b'\x42' * 32
            ikm_b   = b'\xAB' * 32
            salt    = b"saltsalt12345678"
            info_a  = b"nextssl-test-info"
            info_b  = b"nextssl-other-info"
            pk2     = ctypes.create_string_buffer(pk_size)
            sk2     = ctypes.create_string_buffer(sk_size)
            pk3     = ctypes.create_string_buffer(pk_size)
            sk3     = ctypes.create_string_buffer(sk_size)
            pk4     = ctypes.create_string_buffer(pk_size)
            sk4     = ctypes.create_string_buffer(sk_size)

            r1 = fn(ikm_a, len(ikm_a), salt, len(salt), info_a, len(info_a), pk1, sk1)
            r2 = fn(ikm_a, len(ikm_a), salt, len(salt), info_a, len(info_a), pk2, sk2)
            _dbg(debug, f"{fn_name}/kdf r1={r1} r2={r2}", "")
            _dbg(debug, f"{fn_name}/kdf pk1[0:8]", pk1.raw[:8], hex_dump=True)

            # Test 17: non-zero output
            if r1 == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={r1}",
                             debug_data={"pk": pk1.raw, "sk": sk1.raw} if debug else None)

            # Test 18: determinism
            if r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}",
                             debug_data={"pk1": pk1.raw, "pk2": pk2.raw} if debug else None)

            # Test 19: uniqueness — different ikm → different keys
            r3 = fn(ikm_b, len(ikm_b), salt, len(salt), info_a, len(info_a), pk3, sk3)
            _dbg(debug, f"{fn_name}/kdf pk3[0:8]", pk3.raw[:8], hex_dump=True)
            if r3 == 0 and pk1.raw != pk3.raw:
                results.ok(f"{fn_name} (uniqueness — different ikm)")
            else:
                results.fail(f"{fn_name} (uniqueness — different ikm)",
                             reason=f"r3={r3} pk_match={pk1.raw==pk3.raw}",
                             debug_data={"pk1": pk1.raw, "pk3": pk3.raw} if debug else None)

            # Test 20: uniqueness — different info → different keys
            r4 = fn(ikm_a, len(ikm_a), salt, len(salt), info_b, len(info_b), pk4, sk4)
            _dbg(debug, f"{fn_name}/kdf pk4[0:8]", pk4.raw[:8], hex_dump=True)
            if r4 == 0 and pk1.raw != pk4.raw:
                results.ok(f"{fn_name} (uniqueness — different info)")
            else:
                results.fail(f"{fn_name} (uniqueness — different info)",
                             reason=f"r4={r4} pk_match={pk1.raw==pk4.raw}",
                             debug_data={"pk1": pk1.raw, "pk4": pk4.raw} if debug else None)

        elif mode == 'udbf':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_char_p,
            ]
            fn.restype  = ctypes.c_int
            entropy = b'\x37' * 64

            r1 = fn(entropy, len(entropy), pk1, sk1)
            _dbg(debug, f"{fn_name}/udbf r1={r1}", "")
            _dbg(debug, f"{fn_name}/udbf pk1[0:8]", pk1.raw[:8], hex_dump=True)

            # Test 21: non-zero output
            if r1 == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={r1}",
                             debug_data={"pk": pk1.raw, "sk": sk1.raw} if debug else None)
