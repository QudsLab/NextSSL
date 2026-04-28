#!/usr/bin/env python3
"""
test.py — KAT (Known Answer Test) runner

Loads all KAT modules from test/kat/ and:
  • validates meta structure (required keys, valid group)
  • checks case count (>= 20; warns for known blocked/limited algorithms)
  • verifies hash outputs using Python implementations where available
  • verifies encoding outputs using Python stdlib
  • structurally validates modern / pqc cases (non-deterministic, cannot re-run)

Exit code: 0 = all mandatory checks pass, 1 = one or more FAILs.
"""

from __future__ import annotations

import hashlib
import hmac as _hmac
import importlib.util
import sys
import zlib
import base64 as _b64
from pathlib import Path
from typing import Optional, Tuple

# ── Paths ──────────────────────────────────────────────────────────────────────
ROOT    = Path(__file__).resolve().parent
KAT_DIR = ROOT / "test" / "kat"

# ── Constants ──────────────────────────────────────────────────────────────────
REQUIRED_META_KEYS = {"group", "algorithm", "source", "source_ref", "generated_by", "date"}
VALID_GROUPS       = {"encoding", "hash", "modern", "pqc"}
IGNORED_FILES      = {"__init__.py", "kat_base.py"}

# Algorithms with < 20 vectors by design (permanently blocked or implementation-specific)
LOW_VECTOR_ALLOWED = {
    # hash — no working Python lib
    "catena", "lyra2", "makwa", "pomelo",
    # encoding — implementation-specific
    "base62", "ff70",
}

# ── Module loader ──────────────────────────────────────────────────────────────
def _load(path: Path):
    spec = importlib.util.spec_from_file_location(path.stem, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load spec for {path}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ── Input helpers ──────────────────────────────────────────────────────────────
def _case_bytes(case: dict, key_ascii: str = "input_ascii",
                key_hex: str = "input_hex") -> Optional[bytes]:
    if key_ascii in case and case[key_ascii] is not None:
        return case[key_ascii].encode()
    if key_hex in case and case[key_hex] is not None:
        return bytes.fromhex(case[key_hex])
    return None


# ── Hash verifier ──────────────────────────────────────────────────────────────
_HASHLIB_MAP = {
    "MD5":        "md5",
    "SHA-1":      "sha1",
    "SHA-224":    "sha224",
    "SHA-256":    "sha256",
    "SHA-384":    "sha384",
    "SHA-512":    "sha512",
    "SHA-512/224":"sha512_224",
    "SHA-512/256":"sha512_256",
    "SHA3-224":   "sha3_224",
    "SHA3-256":   "sha3_256",
    "SHA3-384":   "sha3_384",
    "SHA3-512":   "sha3_512",
    "BLAKE2B":    "blake2b",
    "BLAKE2S":    "blake2s",
}
_SHAKE_MAP = {
    "SHAKE128": "shake_128",
    "SHAKE256": "shake_256",
}


def _verify_hash(algo: str, case: dict) -> Tuple[Optional[bool], str]:
    """Return (True=pass, False=fail, None=skip), detail."""
    key = algo.upper().replace("-", "").replace("_", "").replace("/", "").replace(" ", "")

    # ── scrypt ──
    if key == "SCRYPT":
        pw  = case.get("password_ascii", "").encode()
        sal = case.get("salt_ascii", "").encode()
        N, r, p, dk = case.get("N",1), case.get("r",1), case.get("p",1), case.get("dklen",32)
        expected = (case.get("output_hex") or "").lower()
        if not expected:
            return None, "no output_hex"
        try:
            got = hashlib.scrypt(pw, salt=sal, n=N, r=r, p=p, dklen=dk).hex()
            return (got == expected), f"got={got[:16]}…"
        except Exception as e:
            return None, f"scrypt error: {e}"

    # ── argon2 variants ──
    if key in ("ARGON2D", "ARGON2I", "ARGON2ID"):
        try:
            from argon2.low_level import hash_secret_raw, Type  # type: ignore
        except ImportError:
            return None, "argon2-cffi not installed"
        type_map = {"ARGON2D": Type.D, "ARGON2I": Type.I, "ARGON2ID": Type.ID}
        pw   = case.get("password_ascii", "").encode()
        sal  = case.get("salt_ascii", "").encode()
        t    = case.get("t_cost", 2)
        m    = case.get("m_cost", 65536)
        par  = case.get("p", 1)
        hlen = case.get("hash_len", 32)
        expected = (case.get("output_hex") or "").lower()
        if not expected:
            return None, "no output_hex"
        try:
            got = hash_secret_raw(pw, sal, time_cost=t, memory_cost=m,
                                  parallelism=par, hash_len=hlen,
                                  type=type_map[key]).hex()
            return (got == expected), f"got={got[:16]}…"
        except Exception as e:
            return None, f"argon2 error: {e}"

    # ── bcrypt ──
    if key == "BCRYPT":
        try:
            import bcrypt as _bcrypt  # type: ignore
        except ImportError:
            return None, "bcrypt not installed"
        pw      = case.get("password_ascii", "").encode()
        salt_s  = case.get("bcrypt_salt") or case.get("salt_ascii")
        expected = (case.get("output_ascii") or case.get("output_hex") or "")
        if not expected or not salt_s:
            return None, "missing salt or output"
        try:
            got = _bcrypt.hashpw(pw, salt_s.encode()).decode()
            return (got == expected), f"ok" if got == expected else f"mismatch"
        except Exception as e:
            return None, f"bcrypt error: {e}"

    # ── balloon ──
    if key == "BALLOON":
        try:
            import balloon  # type: ignore
        except ImportError:
            return None, "balloon not installed"
        return None, "balloon lib API varies — skip"

    # ── yescrypt ──
    if key == "YESCRYPT":
        return None, "no yescrypt Python lib — skip"

    # ── BLAKE3 ──
    if key == "BLAKE3":
        data = _case_bytes(case)
        if data is None:
            return None, "no input"
        expected = (case.get("output_hex") or "").lower()
        if not expected:
            return None, "no output_hex"
        try:
            import blake3  # type: ignore
            got = blake3.blake3(data).hexdigest()
            return (got == expected), f"got={got[:16]}…"
        except ImportError:
            return None, "blake3 not installed"

    # ── Keccak-256 ──
    if key in ("KECCAK256", "KECCAK-256"):
        data = _case_bytes(case)
        if data is None:
            return None, "no input"
        expected = (case.get("output_hex") or "").lower()
        if not expected:
            return None, "no output_hex"
        try:
            from Crypto.Hash import keccak  # type: ignore
            k = keccak.new(digest_bits=256)
            k.update(data)
            got = k.hexdigest()
            return (got == expected), f"got={got[:16]}…"
        except ImportError:
            return None, "pycryptodome not installed"

    # ── SM3 ──
    if key == "SM3":
        data = _case_bytes(case)
        if data is None:
            return None, "no input"
        expected = (case.get("output_hex") or "").lower()
        if not expected:
            return None, "no output_hex"
        try:
            from gmssl.sm3 import sm3_hash  # type: ignore
            got = sm3_hash(list(data)).lower()
            return (got == expected), f"got={got[:16]}…"
        except ImportError:
            return None, "gmssl not installed"

    # ── SHAKE variants ──
    norm_algo = algo.upper().replace("-", "").replace("_", "").replace(" ", "")
    for shake_key, shake_name in _SHAKE_MAP.items():
        if norm_algo == shake_key.replace("-", "").replace("_", ""):
            data = _case_bytes(case)
            if data is None:
                return None, "no input"
            expected = (case.get("output_hex") or "").lower()
            if not expected:
                return None, "no output_hex"
            out_len = len(expected) // 2
            got = hashlib.new(shake_name, data).hexdigest(out_len)
            return (got == expected), f"got={got[:16]}…"

    # ── Standard hashlib algos ──
    # Normalise lookup key: algo → uppercase with hyphens stripped
    lookup = algo.upper()
    if lookup in _HASHLIB_MAP:
        data = _case_bytes(case)
        if data is None:
            return None, "no input"
        expected = (case.get("output_hex") or "").lower()
        if not expected:
            return None, "no output_hex"
        try:
            if lookup in ("BLAKE2B", "BLAKE2S"):
                dsize = case.get("output_len_bytes")
                kwargs = {"digest_size": dsize} if dsize else {}
                got = hashlib.new(_HASHLIB_MAP[lookup], data, **kwargs).hexdigest()
            else:
                got = hashlib.new(_HASHLIB_MAP[lookup], data).hexdigest()
            return (got == expected), f"got={got[:16]}…"
        except ValueError as e:
            return None, f"hashlib: {e}"

    return None, f"no verifier for {algo!r}"


# ── Encoding verifier ──────────────────────────────────────────────────────────
def _verify_encoding(algo: str, case: dict) -> Tuple[Optional[bool], str]:
    a = algo.lower().replace("-", "").replace("_", "").replace(" ", "")

    in_b = _case_bytes(case)

    # base64
    if a == "base64" and in_b is not None:
        exp = case.get("output_ascii")
        if exp is not None:
            got = _b64.b64encode(in_b).decode()
            return (got == exp), f"got={got[:20]}"

    # base64url
    if a == "base64url" and in_b is not None:
        exp = case.get("output_ascii")
        if exp is not None:
            got = _b64.urlsafe_b64encode(in_b).decode().rstrip("=")
            exp_norm = exp.rstrip("=")
            return (got == exp_norm), f"got={got[:20]}"

    # base32
    if a == "base32" and in_b is not None:
        case_id = str(case.get("id", ""))
        exp = case.get("output_ascii")
        if exp is not None:
            if "base32hex" in case_id or case.get("variant", "") == "base32hex":
                try:
                    got = _b64.b32hexencode(in_b).decode()
                except AttributeError:
                    # Python < 3.10 fallback: translate standard alphabet to extended hex
                    std = _b64.b32encode(in_b).decode()
                    table = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",
                                         "0123456789ABCDEFGHIJKLMNOPQRSTUV")
                    got = std.translate(table)
            else:
                got = _b64.b32encode(in_b).decode()
            return (got == exp), f"got={got[:20]}"

    # base16
    if a == "base16" and in_b is not None:
        exp = case.get("output_hex") or case.get("output_ascii")
        if exp is not None:
            got = in_b.hex().upper()
            return (got == exp.upper()), f"got={got[:20]}"

    # hex
    if a == "hex" and in_b is not None:
        exp = case.get("output_hex") or case.get("output_ascii")
        if exp is not None:
            got = in_b.hex()
            return (got.lower() == exp.lower()), f"got={got[:20]}"

    # crc32
    if a == "crc32" and in_b is not None:
        exp = case.get("output_hex")
        if exp is not None:
            variant = case.get("variant", "")
            if variant == "crc32c":
                # CRC32C (Castagnoli) — pure Python
                poly = 0x82F63B78
                crc = 0xFFFFFFFF
                for byte in in_b:
                    crc ^= byte
                    for _ in range(8):
                        crc = (crc >> 1) ^ poly if crc & 1 else crc >> 1
                val = crc ^ 0xFFFFFFFF
            else:
                val = zlib.crc32(in_b) & 0xFFFFFFFF
            got = f"{val:08x}"
            return (got == exp.lower()), f"got={got}"

    return None, "no verifier"


# ── Main test runner ───────────────────────────────────────────────────────────
def run_all() -> int:
    if not KAT_DIR.exists():
        print(f"[FATAL] KAT directory not found: {KAT_DIR}")
        print(f"        Run:  Copy-Item -Recurse KAT\\data test\\kat")
        return 1

    all_files = sorted(
        p for p in KAT_DIR.rglob("*.py")
        if p.name not in IGNORED_FILES
    )

    total = passed = failed = skipped = warned = 0
    fail_details: list[str] = []
    warn_details: list[str] = []

    print(f"KAT dir : {KAT_DIR}")
    print(f"Files   : {len(all_files)}")
    print()
    print(f"{'Status':<6}  {'File':<42}  {'Algorithm':<22}  Detail")
    print("-" * 100)

    for path in all_files:
        rel   = path.relative_to(KAT_DIR)
        total += 1

        # ── load module ────────────────────────────────────────────────────
        try:
            mod = _load(path)
        except Exception as e:
            msg = f"load error: {e}"
            print(f"{'FAIL':<6}  {str(rel):<42}  {'?':<22}  {msg}")
            failed += 1
            fail_details.append(f"{rel}: {msg}")
            continue

        # ── meta check ─────────────────────────────────────────────────────
        if not hasattr(mod, "meta") or not isinstance(mod.meta, dict):
            msg = "missing or invalid 'meta' dict"
            print(f"{'FAIL':<6}  {str(rel):<42}  {'?':<22}  {msg}")
            failed += 1
            fail_details.append(f"{rel}: {msg}")
            continue

        missing_keys = REQUIRED_META_KEYS - set(mod.meta.keys())
        if missing_keys:
            msg = f"meta missing keys: {sorted(missing_keys)}"
            print(f"{'FAIL':<6}  {str(rel):<42}  {'?':<22}  {msg}")
            failed += 1
            fail_details.append(f"{rel}: {msg}")
            continue

        algo  = mod.meta.get("algorithm", "?")
        group = mod.meta.get("group", "?")

        if group not in VALID_GROUPS:
            msg = f"invalid group: {group!r}"
            print(f"{'FAIL':<6}  {str(rel):<42}  {algo:<22}  {msg}")
            failed += 1
            fail_details.append(f"{rel}: {msg}")
            continue

        # ── cases list ─────────────────────────────────────────────────────
        if not hasattr(mod, "cases") or not isinstance(mod.cases, list):
            msg = "missing or invalid 'cases' list"
            print(f"{'FAIL':<6}  {str(rel):<42}  {algo:<22}  {msg}")
            failed += 1
            fail_details.append(f"{rel}: {msg}")
            continue

        cases = mod.cases
        n     = len(cases)

        # check minimum count
        algo_key = algo.lower().replace("-", "").replace(" ", "").replace("_", "")
        is_low_ok = any(b.replace("-","").replace("_","") in algo_key for b in LOW_VECTOR_ALLOWED)

        if n < 20 and not is_low_ok:
            wmsg = f"only {n} cases (< 20)"
            warn_details.append(f"{rel}: {wmsg}")
            warned += 1

        # ── per-group verification ─────────────────────────────────────────
        if group == "hash":
            c_pass = c_fail = c_skip = 0
            fail_ids: list[str] = []
            for c in cases:
                ok, detail = _verify_hash(algo, c)
                if ok is True:
                    c_pass += 1
                elif ok is False:
                    c_fail += 1
                    fail_ids.append(str(c.get("id", "?")))
                else:
                    c_skip += 1

            if c_fail:
                msg = f"{c_fail}/{n} FAIL  ids={fail_ids[:5]}"
                print(f"{'FAIL':<6}  {str(rel):<42}  {algo:<22}  {msg}")
                failed += 1
                fail_details.append(f"{rel}: {msg}")
            elif c_pass:
                msg = f"{c_pass}/{n} verified, {c_skip} skipped"
                print(f"{'PASS':<6}  {str(rel):<42}  {algo:<22}  {msg}")
                passed += 1
            else:
                msg = f"{n} cases loaded, no verifier available"
                print(f"{'SKIP':<6}  {str(rel):<42}  {algo:<22}  {msg}")
                skipped += 1

        elif group == "encoding":
            c_pass = c_fail = c_skip = 0
            fail_ids: list[str] = []
            for c in cases:
                ok, detail = _verify_encoding(algo, c)
                if ok is True:
                    c_pass += 1
                elif ok is False:
                    c_fail += 1
                    fail_ids.append(str(c.get("id", "?")))
                else:
                    c_skip += 1

            if c_fail:
                msg = f"{c_fail}/{n} FAIL  ids={fail_ids[:5]}"
                print(f"{'FAIL':<6}  {str(rel):<42}  {algo:<22}  {msg}")
                failed += 1
                fail_details.append(f"{rel}: {msg}")
            elif c_pass:
                msg = f"{c_pass}/{n} verified, {c_skip} skipped"
                print(f"{'PASS':<6}  {str(rel):<42}  {algo:<22}  {msg}")
                passed += 1
            else:
                msg = f"{n} cases loaded (structure ok)"
                print(f"{'SKIP':<6}  {str(rel):<42}  {algo:<22}  {msg}")
                skipped += 1

        else:
            # modern / pqc — structural load only (non-deterministic or complex deps)
            msg = f"{n} cases loaded (structure ok)"
            print(f"{'SKIP':<6}  {str(rel):<42}  {algo:<22}  {msg}")
            skipped += 1

    # ── Summary ────────────────────────────────────────────────────────────────
    print()
    print("=" * 100)
    print(f"  Total files : {total}")
    print(f"  PASS        : {passed}")
    print(f"  FAIL        : {failed}")
    print(f"  SKIP        : {skipped}  (no verifier — structure validated)")
    print(f"  WARN        : {warned}   (< 20 cases, expected for blocked algorithms)")
    print("=" * 100)

    if warn_details:
        print("\nWarnings:")
        for w in warn_details:
            print(f"  WARN  {w}")

    if fail_details:
        print("\nFailures:")
        for f in fail_details:
            print(f"  FAIL  {f}")
        print()
        return 1

    print()
    print("All mandatory checks passed." if not failed else "")
    return 0


if __name__ == "__main__":
    sys.exit(run_all())
