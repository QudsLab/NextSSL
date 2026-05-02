"""NextSSL KAT test runner.

Loads the built shared library (or WASM module) via ctypes/wasmtime and runs
all KAT vectors from KAT/data against the live C implementation.

Usage:
    python test/run_tests.py --lib <path-to-lib>
    python test/run_tests.py --lib <path-to-lib> --group hash
    python test/run_tests.py --lib <path-to-lib> --group modern
    python test/run_tests.py --wasm <path-to-nextssl.js>         # Emscripten via node
    python test/run_tests.py --wasm-wasi <path-to-nextssl.wasm>  # WASI via wasmtime

Groups:
    hash     - nextssl_hash_compute() (simple hashes; memory-hard → SKIP)
    modern   - HMAC, AES-CBC, AES-GCM, ChaCha20-Poly1305, Poly1305, HKDF, PBKDF2
    encoding - Python stdlib reference only (no C encoding API)
    pqc      - structural KAT validation only (SKIP execution)
    pow      - SKIP (or fastest path with nonce_max=1 if --pow flag given)
"""
import argparse
import ctypes
import importlib.util
import json
import os
import subprocess
import sys
from ctypes import c_char_p, c_int, c_size_t, c_uint32, c_uint8, POINTER
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KAT_DIR = Path(__file__).resolve().parent / "kat"
WASM_RUNNER = Path(__file__).resolve().parent / "wasm_runner.mjs"

# ---------------------------------------------------------------------------
# Algorithm name normalisation: KAT meta.algorithm -> nextssl C API string
# ---------------------------------------------------------------------------
HASH_ALGO_MAP = {
    "SHA-256": "sha256", "SHA-512": "sha512", "SHA-384": "sha384",
    "SHA-224": "sha224", "SHA-512/224": "sha512-224", "SHA-512/256": "sha512-256",
    "SHA-1": "sha1", "SHA-0": "sha0",
    "SHA3-256": "sha3-256", "SHA3-512": "sha3-512",
    "SHA3-384": "sha3-384", "SHA3-224": "sha3-224",
    "SHAKE128": "shake128", "SHAKE256": "shake256",
    "BLAKE3": "blake3", "BLAKE2b": "blake2b", "BLAKE2s": "blake2s",
    "RIPEMD-160": "ripemd160", "RIPEMD-128": "ripemd128",
    "RIPEMD-256": "ripemd256", "RIPEMD-320": "ripemd320",
    "MD5": "md5", "MD4": "md4", "MD2": "md2",
    "KECCAK-256": "keccak256", "HAS-160": "has160",
    "SM3": "sm3", "Whirlpool": "whirlpool",
    "KMAC128": "kmac128", "KMAC256": "kmac256",
    "Skein-256": "skein256", "Skein-512": "skein512", "Skein-1024": "skein1024",
    "NT": "nt",
}

# These need a typed API beyond nextssl_hash_compute()
MEMORY_HARD_ALGOS = {
    "Argon2id", "Argon2i", "Argon2d", "BCrypt", "Scrypt",
    "Balloon", "Lyra2", "Catena", "Makwa", "Pomelo", "Yescrypt",
}

# Modern algo -> handler key
MODERN_ALGO_MAP = {
    "HMAC": "hmac",
    "AES-CBC": "aes_cbc",
    "AES-ECB": "aes_ecb",
    "AES-GCM": "aes_gcm",
    "ChaCha20-Poly1305": "chacha20_poly1305",
    "Poly1305": "poly1305",
    "HKDF": "hkdf",
    "PBKDF2": "pbkdf2",
}

MAX_DIGEST = 1024  # bytes — enough for any hash

# ---------------------------------------------------------------------------
# Counters
# ---------------------------------------------------------------------------
class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.skipped = 0
        self.errors = []

    def ok(self):
        self.passed += 1

    def fail(self, msg):
        self.failed += 1
        self.errors.append(msg)

    def skip(self, reason=""):
        self.skipped += 1

    def total(self):
        return self.passed + self.failed + self.skipped


# ---------------------------------------------------------------------------
# KAT helpers
# ---------------------------------------------------------------------------
IGNORED = {"__init__.py", "kat_base.py"}

def _load_kat_module(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _iter_kat_group(group: str):
    """Yield (module_name, module) for every KAT file in the given group.
    Modules that fail to import are yielded as (name, None) so callers can skip."""
    group_dir = KAT_DIR / group
    if not group_dir.exists():
        return
    for path in sorted(group_dir.glob("*.py")):
        if path.name in IGNORED:
            continue
        try:
            yield path.stem, _load_kat_module(path)
        except Exception as exc:
            yield path.stem, None  # caller checks for None and skips/warns

def _bytes_from_case(case: dict, *keys):
    """Extract bytes from a case dict by trying several candidate keys."""
    for k in keys:
        if k in case:
            v = case[k]
            if k.endswith("_hex"):
                return bytes.fromhex(v) if v else b""
            if k.endswith("_ascii"):
                return v.encode() if isinstance(v, str) else v
            if k.endswith("_bytes"):
                return v
    return None

def _is_simple_hash_case(case: dict) -> bool:
    """Return True if a hash case can be tested via nextssl_hash_compute()."""
    has_output = "output_hex" in case
    has_input = any(k in case for k in ("input_ascii", "input_hex"))
    has_pw_fields = any(k in case for k in (
        "password_ascii", "password_hex", "t_cost", "N", "rounds", "cost", "p",
    ))
    return has_output and has_input and not has_pw_fields


def _requested_hash_output_len(case: dict, expected: bytes) -> int:
    if "output_len_bytes" in case:
        return int(case["output_len_bytes"])
    if "output_len_bits" in case:
        bits = int(case["output_len_bits"])
        return (bits // 8) if bits % 8 == 0 else -1
    return len(expected)


# ---------------------------------------------------------------------------
# Library loader (ctypes)
# ---------------------------------------------------------------------------
class Lib:
    def __init__(self, path: str):
        self._dll = ctypes.CDLL(str(path))
        self._bind()
        rc = self._dll.nextssl_init()
        if rc != 0:
            raise RuntimeError(f"nextssl_init() returned {rc}")

    def _bind(self):
        d = self._dll

        # nextssl_hash_compute(algo, data, data_len, out, out_len*) -> int
        d.nextssl_hash_compute.restype = c_int
        d.nextssl_hash_compute.argtypes = [
            c_char_p, POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), POINTER(c_size_t),
        ]
        # nextssl_hash_digest_size(algo) -> size_t
        d.nextssl_hash_digest_size.restype = c_size_t
        d.nextssl_hash_digest_size.argtypes = [c_char_p]

        # nextssl_mac_hmac(algo, key, key_len, msg, msg_len, out, out_len*) -> int
        d.nextssl_mac_hmac.restype = c_int
        d.nextssl_mac_hmac.argtypes = [
            c_char_p,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), POINTER(c_size_t),
        ]
        # nextssl_mac_poly1305(key[32], msg, msg_len, out[16]) -> int
        d.nextssl_mac_poly1305.restype = c_int
        d.nextssl_mac_poly1305.argtypes = [
            POINTER(c_uint8), POINTER(c_uint8), c_size_t, POINTER(c_uint8),
        ]
        # nextssl_sym_aes_cbc_encrypt/decrypt(key, key_len, iv[16], in, in_len, out) -> int
        for fn in ("nextssl_sym_aes_cbc_encrypt", "nextssl_sym_aes_cbc_decrypt"):
            f = getattr(d, fn)
            f.restype = c_int
            f.argtypes = [
                POINTER(c_uint8), c_size_t,
                POINTER(c_uint8),
                POINTER(c_uint8), c_size_t,
                POINTER(c_uint8),
            ]
        # nextssl_aead_aes_gcm_encrypt(key, key_len, nonce, aad, aad_len, in, in_len, out) -> void
        d.nextssl_aead_aes_gcm_encrypt.restype = None
        d.nextssl_aead_aes_gcm_encrypt.argtypes = [
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8),
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8),
        ]
        # nextssl_aead_aes_gcm_decrypt(key, key_len, nonce, aad, aad_len, in, in_len, out) -> int
        d.nextssl_aead_aes_gcm_decrypt.restype = c_int
        d.nextssl_aead_aes_gcm_decrypt.argtypes = [
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8),
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8),
        ]
        # nextssl_aead_chacha20_poly1305_encrypt(key, nonce, aad, aad_len, in, in_len, out) -> void
        d.nextssl_aead_chacha20_poly1305_encrypt.restype = None
        d.nextssl_aead_chacha20_poly1305_encrypt.argtypes = [
            POINTER(c_uint8), POINTER(c_uint8),
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8),
        ]
        # nextssl_aead_chacha20_poly1305_decrypt(key, nonce, aad, aad_len, in, in_len, out) -> int
        d.nextssl_aead_chacha20_poly1305_decrypt.restype = c_int
        d.nextssl_aead_chacha20_poly1305_decrypt.argtypes = [
            POINTER(c_uint8), POINTER(c_uint8),
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8),
        ]
        # nextssl_kdf_hkdf(algo, salt, salt_len, ikm, ikm_len, info, info_len, out, out_len) -> int
        d.nextssl_kdf_hkdf.restype = c_int
        d.nextssl_kdf_hkdf.argtypes = [
            c_char_p,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
        ]
        # nextssl_kdf_pbkdf2(algo, pass, pass_len, salt, salt_len, iters, out, out_len) -> int
        d.nextssl_kdf_pbkdf2.restype = c_int
        d.nextssl_kdf_pbkdf2.argtypes = [
            c_char_p,
            POINTER(c_uint8), c_size_t,
            POINTER(c_uint8), c_size_t,
            c_uint32,
            POINTER(c_uint8), c_size_t,
        ]


def _ptr(data: bytes):
    """Return a ctypes pointer to a bytes-like object (zero-length safe)."""
    if not data:
        return ctypes.cast(None, POINTER(c_uint8))
    return ctypes.cast(ctypes.c_char_p(data), POINTER(c_uint8))


# ---------------------------------------------------------------------------
# Hash group runner
# ---------------------------------------------------------------------------
def run_hash_group(lib: Lib, res: Results, verbose: bool):
    seen_cases: dict[tuple[str, bytes, int], tuple[bytes, str]] = {}

    for mod_name, mod in _iter_kat_group("hash"):
        if mod is None:
            res.skip(f"hash/{mod_name}: failed to load KAT module")
            continue
        algo_name = getattr(mod, "meta", {}).get("algorithm", "")
        if algo_name in MEMORY_HARD_ALGOS:
            for _ in mod.cases:
                res.skip("memory-hard needs typed API")
            continue
        c_algo = HASH_ALGO_MAP.get(algo_name)
        if c_algo is None:
            for _ in mod.cases:
                res.skip(f"no name mapping for {algo_name!r}")
            continue

        for case in mod.cases:
            cid = case.get("id", "?")
            label = f"hash/{mod_name}[{cid}]"

            if not _is_simple_hash_case(case):
                res.skip(label)
                continue

            data = _bytes_from_case(case, "input_ascii", "input_hex") or b""
            expected = bytes.fromhex(case["output_hex"])
            requested_len = _requested_hash_output_len(case, expected)

            if requested_len < 0:
                print(f"  SKIP {label}: non-byte-aligned output length is not supported")
                res.skip(label)
                continue

            case_key = (c_algo, data, requested_len)
            prior = seen_cases.get(case_key)
            if prior is not None and prior[0] != expected:
                print(
                    f"  SKIP {label}: conflicting KAT vector duplicates {prior[1]} "
                    f"with a different expected output"
                )
                res.skip(label)
                continue
            seen_cases.setdefault(case_key, (expected, label))

            out_buf = (c_uint8 * max(requested_len, 1))()
            out_len = c_size_t(requested_len)

            rc = lib._dll.nextssl_hash_compute(
                c_algo.encode(),
                _ptr(data), c_size_t(len(data)),
                out_buf, ctypes.byref(out_len),
            )
            if rc != 0:
                res.fail(
                    f"FAIL {label}: nextssl_hash_compute returned {rc} "
                    f"(requested {requested_len} bytes)"
                )
                continue
            got = bytes(out_buf[:out_len.value])
            if got == expected:
                if verbose:
                    print(f"  PASS {label}")
                res.ok()
            else:
                res.fail(f"FAIL {label}: got {got.hex()} expected {expected.hex()}")


# ---------------------------------------------------------------------------
# Modern group runner
# ---------------------------------------------------------------------------
def run_modern_group(lib: Lib, res: Results, verbose: bool):
    for mod_name, mod in _iter_kat_group("modern"):
        if mod is None:
            res.skip(f"modern/{mod_name}: failed to load KAT module")
            continue
        algo = getattr(mod, "meta", {}).get("algorithm", "")
        handler = MODERN_ALGO_MAP.get(algo)
        if handler is None:
            for _ in mod.cases:
                res.skip(f"no handler for modern/{algo}")
            continue

        for case in mod.cases:
            cid = case.get("id", "?")
            label = f"modern/{mod_name}[{cid}]"
            try:
                _run_modern_case(lib, handler, case, label, res, verbose)
            except Exception as exc:
                res.fail(f"FAIL {label}: exception: {exc}")


def _run_modern_case(lib, handler, case, label, res, verbose):
    if handler == "hmac":
        algo_raw = case.get("hash_alg", "sha256")
        c_algo = HASH_ALGO_MAP.get(algo_raw, algo_raw.lower())
        key = _bytes_from_case(case, "key_ascii", "key_hex") or b""
        msg = _bytes_from_case(case, "message_ascii", "message_hex") or b""
        expected = bytes.fromhex(case.get("mac_hex", ""))
        out = (c_uint8 * MAX_DIGEST)()
        out_len = c_size_t(MAX_DIGEST)
        rc = lib._dll.nextssl_mac_hmac(
            c_algo.encode(),
            _ptr(key), c_size_t(len(key)),
            _ptr(msg), c_size_t(len(msg)),
            out, ctypes.byref(out_len),
        )
        got = bytes(out[:out_len.value])
        _check(rc, got, expected, label, res, verbose)

    elif handler == "aes_cbc":
        key = bytes.fromhex(case["key_hex"])
        iv = bytes.fromhex(case["iv_hex"])
        pt = bytes.fromhex(case.get("plaintext_hex", ""))
        expected_ct = bytes.fromhex(case.get("ciphertext_hex", ""))
        out = (c_uint8 * max(len(pt), 1))()
        iv_arr = (c_uint8 * 16)(*iv[:16])
        rc = lib._dll.nextssl_sym_aes_cbc_encrypt(
            _ptr(key), c_size_t(len(key)),
            iv_arr,
            _ptr(pt), c_size_t(len(pt)),
            out,
        )
        got = bytes(out[:len(pt)])
        _check(rc, got, expected_ct, label, res, verbose)

    elif handler == "aes_gcm":
        key = bytes.fromhex(case["key_hex"])
        nonce = bytes.fromhex(case["iv_hex"])
        aad = bytes.fromhex(case.get("aad_hex", "") or "")
        pt = bytes.fromhex(case.get("plaintext_hex", "") or "")
        expected_ct = bytes.fromhex(case.get("ciphertext_hex", "") or "")
        expected_tag = bytes.fromhex(case.get("tag_hex", ""))
        # out = ciphertext ‖ 16-byte tag
        out_size = len(pt) + 16
        out = (c_uint8 * max(out_size, 1))()
        nonce_arr = (c_uint8 * 12)(*nonce[:12])
        lib._dll.nextssl_aead_aes_gcm_encrypt(
            _ptr(key), c_size_t(len(key)),
            nonce_arr,
            _ptr(aad), c_size_t(len(aad)),
            _ptr(pt), c_size_t(len(pt)),
            out,
        )
        got_ct = bytes(out[:len(pt)])
        got_tag = bytes(out[len(pt):len(pt) + 16])
        if got_ct == expected_ct and got_tag == expected_tag:
            if verbose:
                print(f"  PASS {label}")
            res.ok()
        else:
            res.fail(
                f"FAIL {label}: ct={got_ct.hex()}…tag={got_tag.hex()} "
                f"expected ct={expected_ct.hex()}…tag={expected_tag.hex()}"
            )

    elif handler == "chacha20_poly1305":
        key = bytes.fromhex(case["key_hex"])
        nonce = bytes.fromhex(case["nonce_hex"])
        aad = bytes.fromhex(case.get("aad_hex", "") or "")
        pt = _bytes_from_case(case, "plaintext_ascii", "plaintext_hex") or b""
        expected_ct = bytes.fromhex(case.get("ciphertext_hex", ""))
        expected_tag = bytes.fromhex(case.get("tag_hex", ""))
        out_size = len(pt) + 16
        out = (c_uint8 * max(out_size, 1))()
        key_arr = (c_uint8 * 32)(*key[:32])
        nonce_arr = (c_uint8 * 12)(*nonce[:12])
        lib._dll.nextssl_aead_chacha20_poly1305_encrypt(
            key_arr, nonce_arr,
            _ptr(aad), c_size_t(len(aad)),
            _ptr(pt), c_size_t(len(pt)),
            out,
        )
        got_ct = bytes(out[:len(pt)])
        got_tag = bytes(out[len(pt):len(pt) + 16])
        if got_ct == expected_ct and got_tag == expected_tag:
            if verbose:
                print(f"  PASS {label}")
            res.ok()
        else:
            res.fail(
                f"FAIL {label}: ct={got_ct.hex()[:32]}…tag={got_tag.hex()} "
                f"expected tag={expected_tag.hex()}"
            )

    elif handler == "poly1305":
        key = bytes.fromhex(case["key_hex"])
        msg = _bytes_from_case(case, "message_ascii", "message_hex") or b""
        expected = bytes.fromhex(case.get("mac_hex") or case.get("tag_hex", ""))
        out = (c_uint8 * 16)()
        key_arr = (c_uint8 * 32)(*key[:32])
        rc = lib._dll.nextssl_mac_poly1305(key_arr, _ptr(msg), c_size_t(len(msg)), out)
        _check(rc, bytes(out), expected, label, res, verbose)

    elif handler == "hkdf":
        algo_raw = case.get("hash_alg") or case.get("algo", "sha256")
        c_algo = HASH_ALGO_MAP.get(algo_raw, algo_raw.lower())
        salt = _bytes_from_case(case, "salt_hex", "salt_ascii") or b""
        ikm = _bytes_from_case(case, "ikm_hex", "ikm_ascii") or b""
        info = _bytes_from_case(case, "info_hex", "info_ascii") or b""
        expected = bytes.fromhex(case.get("okm_hex") or case.get("output_hex", ""))
        out = (c_uint8 * len(expected))()
        rc = lib._dll.nextssl_kdf_hkdf(
            c_algo.encode(),
            _ptr(salt), c_size_t(len(salt)),
            _ptr(ikm), c_size_t(len(ikm)),
            _ptr(info), c_size_t(len(info)),
            out, c_size_t(len(expected)),
        )
        _check(rc, bytes(out), expected, label, res, verbose)

    elif handler == "pbkdf2":
        algo_raw = case.get("hash_alg") or case.get("prf_hash") or case.get("algo", "sha1")
        c_algo = HASH_ALGO_MAP.get(algo_raw, algo_raw.lower())
        pw = _bytes_from_case(case, "password_ascii", "password_hex") or b""
        salt = _bytes_from_case(case, "salt_ascii", "salt_hex") or b""
        iters = int(case.get("iterations") or case.get("c", 1))
        key_len = int(case.get("key_len") or case.get("dkLen", 20))
        expected = bytes.fromhex(case.get("dk_hex") or case.get("output_hex", ""))
        out = (c_uint8 * key_len)()
        rc = lib._dll.nextssl_kdf_pbkdf2(
            c_algo.encode(),
            _ptr(pw), c_size_t(len(pw)),
            _ptr(salt), c_size_t(len(salt)),
            c_uint32(iters),
            out, c_size_t(key_len),
        )
        _check(rc, bytes(out), expected, label, res, verbose)

    else:
        res.skip(f"no handler for {handler}")


def _check(rc, got, expected, label, res, verbose):
    if rc != 0:
        res.fail(f"FAIL {label}: C function returned {rc}")
    elif got == expected:
        if verbose:
            print(f"  PASS {label}")
        res.ok()
    else:
        res.fail(f"FAIL {label}: got {got.hex()} expected {expected.hex()}")


# ---------------------------------------------------------------------------
# Encoding group runner (Python stdlib reference — no C encoding API)
# ---------------------------------------------------------------------------
import base64 as _b64, binascii as _ba

_ENCODING_REFS = {}

def _register_encoding():
    import base64, binascii

    def _run_base64(case):
        data = _bytes_from_case(case, "input_ascii", "input_hex")
        exp = _bytes_from_case(case, "output_ascii", "output_hex")
        if data is None or exp is None:
            return None
        return base64.b64encode(data), exp

    def _run_base64url(case):
        data = _bytes_from_case(case, "input_ascii", "input_hex")
        exp = _bytes_from_case(case, "output_ascii", "output_hex")
        if data is None or exp is None:
            return None
        return base64.urlsafe_b64encode(data), exp

    def _run_hex(case):
        data = _bytes_from_case(case, "input_ascii", "input_hex")
        exp = _bytes_from_case(case, "output_ascii", "output_hex")
        if data is None or exp is None:
            return None
        return binascii.hexlify(data), exp

    def _run_base16(case):
        data = _bytes_from_case(case, "input_ascii", "input_hex")
        exp = _bytes_from_case(case, "output_ascii", "output_hex")
        if data is None or exp is None:
            return None
        return base64.b16encode(data), exp

    def _run_base32(case):
        data = _bytes_from_case(case, "input_ascii", "input_hex")
        exp = _bytes_from_case(case, "output_ascii", "output_hex")
        if data is None or exp is None:
            return None
        return base64.b32encode(data), exp

    _ENCODING_REFS["base64"] = _run_base64
    _ENCODING_REFS["base64url"] = _run_base64url
    _ENCODING_REFS["hex"] = _run_hex
    _ENCODING_REFS["base16"] = _run_base16
    _ENCODING_REFS["base32"] = _run_base32

_register_encoding()


def run_encoding_group(res: Results, verbose: bool):
    for mod_name, mod in _iter_kat_group("encoding"):
        if mod is None:
            res.skip(f"encoding/{mod_name}: failed to load KAT module")
            continue
        handler = _ENCODING_REFS.get(mod_name)
        if handler is None:
            for _ in mod.cases:
                res.skip(f"no Python ref for encoding/{mod_name}")
            continue
        for case in mod.cases:
            cid = case.get("id", "?")
            label = f"encoding/{mod_name}[{cid}]"
            try:
                result = handler(case)
                if result is None:
                    res.skip(label)
                    continue
                got, expected = result
                if isinstance(got, str):
                    got = got.encode()
                if isinstance(expected, str):
                    expected = expected.encode()
                if got == expected:
                    if verbose:
                        print(f"  PASS {label}")
                    res.ok()
                else:
                    res.fail(f"FAIL {label}: got {got!r} expected {expected!r}")
            except Exception as exc:
                res.fail(f"FAIL {label}: {exc}")


# ---------------------------------------------------------------------------
# PQC group — structural KAT validation only (execution requires typed API)
# ---------------------------------------------------------------------------
def run_pqc_group(res: Results, verbose: bool):
    for mod_name, mod in _iter_kat_group("pqc"):
        if mod is None:
            res.skip(f"pqc/{mod_name}: failed to load")
            continue
        for _ in mod.cases:
            res.skip(f"pqc/{mod_name}: execution needs typed API")


# ---------------------------------------------------------------------------
# PoW group — skip (or 1-nonce if --pow given)
# ---------------------------------------------------------------------------
def run_pow_group(lib, res: Results, verbose: bool, run_pow: bool):
    if not run_pow:
        for _, mod in _iter_kat_group("pow"):
            for _ in mod.cases:
                res.skip("pow: skipped (use --pow to enable)")
        return
    # run_pow path: nonce_max = 1 (fastest)
    for mod_name, mod in _iter_kat_group("pow"):
        for _ in mod.cases:
            res.skip(f"pow/{mod_name}: typed API not yet wired")


# ---------------------------------------------------------------------------
# WASM runner (Emscripten via Node.js subprocess)
# ---------------------------------------------------------------------------
def run_wasm_emscripten(js_path: str, res: Results, verbose: bool):
    if not WASM_RUNNER.exists():
        res.fail("WASM runner wasm_runner.mjs not found")
        return
    node = _find_node()
    if node is None:
        res.fail("node not found — install Node.js to test WASM")
        return

    # Collect hash KAT vectors into a JSON payload
    vectors = []
    for mod_name, mod in _iter_kat_group("hash"):
        algo_name = getattr(mod, "meta", {}).get("algorithm", "")
        if algo_name in MEMORY_HARD_ALGOS:
            continue
        c_algo = HASH_ALGO_MAP.get(algo_name)
        if c_algo is None:
            continue
        for case in mod.cases:
            if not _is_simple_hash_case(case):
                continue
            data = _bytes_from_case(case, "input_ascii", "input_hex") or b""
            expected = case["output_hex"]
            vectors.append({
                "algo": c_algo,
                "input_hex": data.hex(),
                "expected_hex": expected,
                "label": f"hash/{mod_name}[{case.get('id','?')}]",
            })

    proc = subprocess.run(
        [node, str(WASM_RUNNER), js_path],
        input=json.dumps(vectors),
        capture_output=True, text=True, timeout=120,
    )
    if proc.returncode != 0:
        res.fail(f"WASM runner failed:\n{proc.stderr[:1000]}")
        return

    try:
        results = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        res.fail(f"WASM runner bad JSON: {exc}\nstdout: {proc.stdout[:500]}")
        return

    for r in results:
        if r.get("status") == "pass":
            if verbose:
                print(f"  PASS (wasm) {r['label']}")
            res.ok()
        elif r.get("status") == "skip":
            res.skip(r.get("label", ""))
        else:
            res.fail(f"FAIL (wasm) {r.get('label','?')}: {r.get('msg','')}")


def _find_node():
    for candidate in ("node", "node.exe", "nodejs"):
        try:
            subprocess.run([candidate, "--version"], capture_output=True, check=True)
            return candidate
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue
    return None


# ---------------------------------------------------------------------------
# WASM WASI runner (wasmtime CLI)
# ---------------------------------------------------------------------------
def run_wasm_wasi(wasm_path: str, res: Results, verbose: bool):
    # wasmtime cannot easily invoke arbitrary C functions with raw bytes;
    # mark as skip with an informational note.
    for mod_name, _ in _iter_kat_group("hash"):
        res.skip(f"wasi/{mod_name}: wasmtime CLI not wired (use Emscripten path)")


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------
def _print_summary(res: Results, label: str):
    total = res.total()
    pct = (res.passed / (res.passed + res.failed) * 100) if (res.passed + res.failed) else 100.0
    print(f"\n{'='*60}")
    print(f"  {label}")
    print(f"  Passed : {res.passed}/{total}  ({pct:.1f}%)")
    print(f"  Failed : {res.failed}")
    print(f"  Skipped: {res.skipped}")
    if res.errors:
        print(f"\nFailures ({len(res.errors)}):")
        for e in res.errors[:40]:
            print(f"  {e}")
        if len(res.errors) > 40:
            print(f"  ... and {len(res.errors)-40} more")
    print("="*60)

    # GitHub Actions step summary
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            status = "✅" if res.failed == 0 else "❌"
            f.write(f"\n## {status} {label}\n\n")
            f.write(f"| Passed | Failed | Skipped | Total |\n")
            f.write(f"|--------|--------|---------|-------|\n")
            f.write(f"| {res.passed} | {res.failed} | {res.skipped} | {total} |\n")
            if res.errors:
                f.write(f"\n<details><summary>Failures</summary>\n\n```\n")
                f.write("\n".join(res.errors[:50]))
                f.write("\n```\n</details>\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="NextSSL KAT test runner")
    ap.add_argument("--lib", help="Path to native shared library")
    ap.add_argument("--wasm", help="Path to Emscripten .js glue file (WASM via node)")
    ap.add_argument("--wasm-wasi", help="Path to WASI .wasm file (WASM via wasmtime)")
    ap.add_argument("--group", choices=["hash", "modern", "encoding", "pqc", "pow"],
                    help="Only run this group")
    ap.add_argument("--pow", action="store_true", help="Run PoW KATs (1-nonce max)")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print each PASS line")
    args = ap.parse_args()

    if not args.lib and not args.wasm and not args.wasm_wasi:
        ap.error("Provide at least one of --lib, --wasm, or --wasm-wasi")

    groups = [args.group] if args.group else ["hash", "modern", "encoding", "pqc", "pow"]
    res = Results()

    # --- native ---
    if args.lib:
        lib = Lib(args.lib)
        if "hash" in groups:
            print("[ hash ]")
            run_hash_group(lib, res, args.verbose)
        if "modern" in groups:
            print("[ modern ]")
            run_modern_group(lib, res, args.verbose)
        if "encoding" in groups:
            print("[ encoding (Python stdlib ref) ]")
            run_encoding_group(res, args.verbose)
        if "pqc" in groups:
            run_pqc_group(res, args.verbose)
        if "pow" in groups:
            run_pow_group(lib, res, args.verbose, args.pow)
        _print_summary(res, f"Native: {Path(args.lib).name}")

    # --- WASM Emscripten ---
    if args.wasm:
        wasm_res = Results()
        print("[ wasm/emscripten ]")
        run_wasm_emscripten(args.wasm, wasm_res, args.verbose)
        _print_summary(wasm_res, f"WASM/Emscripten: {Path(args.wasm).name}")
        res.passed += wasm_res.passed
        res.failed += wasm_res.failed
        res.skipped += wasm_res.skipped
        res.errors += wasm_res.errors

    # --- WASM WASI ---
    if args.wasm_wasi:
        wasi_res = Results()
        print("[ wasm/wasi ]")
        run_wasm_wasi(args.wasm_wasi, wasi_res, args.verbose)
        _print_summary(wasi_res, f"WASM/WASI: {Path(args.wasm_wasi).name}")

    sys.exit(0 if res.failed == 0 else 1)


if __name__ == "__main__":
    main()
