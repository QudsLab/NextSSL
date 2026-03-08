"""script/test/core/keygen_runner.py — one-shot keygen round-trip runner.

run_keygen_oneshotmodes() exercises every requested mode for one algorithm
and verifies both correctness (non-zero keys) and determinism.
"""
import ctypes
from .result import Results


def run_keygen_oneshotmodes(
    lib,
    algo:    str,
    pk_size: int,
    sk_size: int,
    modes:   list,
    results: Results,
) -> None:
    """For each mode in *modes*, call keygen_<algo>_<mode>(...) and verify:
      - return value == 0
      - pk and sk buffers are non-zero
      - drbg / password / hd modes produce identical output for identical input
        (determinism check)

    Function signatures by mode:
      random   : (pk, sk)
      drbg     : (pk, sk, seed, seed_len)
      password : (pk, sk, pwd, pwd_len, salt, salt_len)
      hd       : (pk, sk, master, master_len, index:uint32)
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
            ret = fn(pk1, sk1)
            if ret == 0 and any(pk1.raw) and any(sk1.raw):
                results.ok(f"{fn_name} (non-zero output)")
            else:
                results.fail(f"{fn_name} (non-zero output)", reason=f"ret={ret}")

        elif mode == 'drbg':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t,
            ]
            fn.restype  = ctypes.c_int
            seed = b'\x42' * 32
            pk2  = ctypes.create_string_buffer(pk_size)
            sk2  = ctypes.create_string_buffer(sk_size)
            r1 = fn(pk1, sk1, seed, len(seed))
            r2 = fn(pk2, sk2, seed, len(seed))
            ok = r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw
            if ok:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}")

        elif mode == 'password':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_char_p, ctypes.c_size_t,
            ]
            fn.restype  = ctypes.c_int
            pwd  = b"nextssl_test_password"
            salt = b"saltsalt12345678"
            pk2  = ctypes.create_string_buffer(pk_size)
            sk2  = ctypes.create_string_buffer(sk_size)
            r1 = fn(pk1, sk1, pwd, len(pwd), salt, len(salt))
            r2 = fn(pk2, sk2, pwd, len(pwd), salt, len(salt))
            ok = r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw
            if ok:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}")

        elif mode == 'hd':
            fn.argtypes = [
                ctypes.c_char_p, ctypes.c_char_p,
                ctypes.c_char_p, ctypes.c_size_t,
                ctypes.c_uint32,
            ]
            fn.restype  = ctypes.c_int
            master = b'\xBB' * 32
            idx    = ctypes.c_uint32(0)
            pk2    = ctypes.create_string_buffer(pk_size)
            sk2    = ctypes.create_string_buffer(sk_size)
            r1 = fn(pk1, sk1, master, len(master), idx)
            r2 = fn(pk2, sk2, master, len(master), idx)
            ok = r1 == 0 and r2 == 0 and pk1.raw == pk2.raw and sk1.raw == sk2.raw
            if ok:
                results.ok(f"{fn_name} (deterministic)")
            else:
                results.fail(f"{fn_name} (deterministic)",
                             reason=f"r1={r1} r2={r2} pk_match={pk1.raw==pk2.raw}")
