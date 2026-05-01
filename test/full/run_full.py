#!/usr/bin/env python3
"""Full KAT runner — runs every algorithm group against every variant.

Wraps  test/run_tests.py  for each selected variant.  Every KAT vector for
every supported algorithm is exercised (hash, modern, encoding, pqc-struct,
pow-1-nonce).  No algorithm can be silently skipped.

Usage
-----
  # Full KAT for all 29 variants
  python test/full/run_full.py

  # Windows + Linux glibc only
  python test/full/run_full.py -R 11-28

  # Android only
  python test/full/run_full.py -R 61-64

  # Single variant
  python test/full/run_full.py --id 42

  # Restrict to one algo group (hash | modern | encoding | pqc | pow)
  python test/full/run_full.py --group hash

  # Custom artifact root
  python test/full/run_full.py --lib-dir /path/to/artifacts

Artifact directory layout  (same as mass runner)
------------------------------------------------
  <lib-dir>/
    11/  nextssl.dll
    21/  libnextssl.so
    51/  nextssl.js  nextssl.wasm
    52/  nextssl.wasm
    ...

Algorithm groups executed per variant
--------------------------------------
  hash     nextssl_hash_compute()
           SHA-256, SHA-512, SHA-384, SHA3-256, SHA3-512,
           BLAKE2b-256, BLAKE2b-512, BLAKE2s-256, BLAKE3,
           MD5, SHA-1, Skein-256, Skein-512
           (memory-hard algos → SKIP: too slow in CI)

  modern   nextssl_mac_hmac(), nextssl_sym_aes_cbc_*(),
           nextssl_aead_aes_gcm_*(), nextssl_aead_chacha20_poly1305_*(),
           nextssl_mac_poly1305(), nextssl_kdf_hkdf(), nextssl_kdf_pbkdf2()

  encoding Python-stdlib reference only (base64, hex, bech32, …)

  pqc      Structural KAT validation (typed API — execution skipped)

  pow      Skipped by default; set --pow for 1-nonce fastest path

Exit codes
----------
  0  all tested variants PASS or SKIP
  1  at least one FAIL
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO = _HERE.parent.parent
sys.path.insert(0, str(_REPO))

from test.variants import ALL_IDS, VARIANTS, Variant, parse_range   # noqa: E402
from test.mass.header_check import HEADER_ONLY_MODES                # noqa: E402

_RUN_TESTS = _REPO / "test" / "run_tests.py"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_binary(art_dir: Path, glob: str) -> "Path | None":
    matches = sorted(art_dir.glob(glob))
    return matches[0] if matches else None


def _art_dir(lib_dir: Path, v: Variant) -> "Path | None":
    by_id = lib_dir / str(v.vid)
    if by_id.is_dir():
        return by_id
    by_name = lib_dir / v.artifact
    if by_name.is_dir():
        return by_name
    return None


def _run_variant(
    v: Variant,
    lib_dir: Path,
    group: "str | None",
    pow_enabled: bool,
    verbose: bool,
) -> tuple[int, str]:
    """Run the full KAT for one variant.

    Returns
    -------
    (returncode, status_message)
    """
    adir = _art_dir(lib_dir, v)
    if adir is None:
        return 0, "SKIP (artifact dir not found)"

    lib = _find_binary(adir, v.lib_glob)
    if lib is None:
        return 0, f"SKIP (no {v.lib_glob} in {adir.name}/)"

    if v.exec_mode in HEADER_ONLY_MODES:
        return 0, "SKIP (header-only mode: KAT execution not possible)"

    # Build command
    cmd = [sys.executable, str(_RUN_TESTS)]

    if v.exec_mode == "node_wasm":
        cmd += ["--wasm", str(lib)]
    elif v.exec_mode == "wasi_wasm":
        cmd += ["--wasm-wasi", str(lib)]
    else:
        cmd += ["--lib", str(lib)]

    if group:
        cmd += ["--group", group]
    if pow_enabled:
        cmd.append("--pow")
    if verbose:
        cmd.append("--verbose")

    try:
        r = subprocess.run(cmd, capture_output=not verbose, text=True)
        rc = r.returncode
        if rc == 0:
            return 0, "PASS"
        tail = (r.stdout or "")[-600:] if not verbose else ""
        return rc, "FAIL (exit={}){}".format(rc, f"\n{tail}" if tail else "")
    except Exception as exc:
        return -1, f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# Summary reporting
# ---------------------------------------------------------------------------

def _marker(status: str) -> str:
    if status == "PASS":
        return "\u2713"
    if status.startswith("FAIL") or status.startswith("ERROR"):
        return "\u2717"
    return "~"


def _write_gha_summary(results: "list[tuple[int, Variant, int, str]]") -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write("## Full KAT — variant results\n\n")
        f.write("| ID | Platform | Arch | Toolchain | Result |\n")
        f.write("|----|----------|------|-----------|--------|\n")
        for vid, v, rc, s in results:
            icon = "\u2705" if s == "PASS" else ("\u26a0\ufe0f" if s.startswith("SKIP") else "\u274c")
            f.write(f"| {vid} | {v.platform} | {v.arch} | {v.toolchain} | {icon} {s} |\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-R", "--range", metavar="SPEC",
        help="Variant ID range, e.g. '11-28', '61-64', '11,21,31'",
    )
    parser.add_argument(
        "--id", type=int, metavar="VID",
        help="Single variant ID (e.g. 42)",
    )
    parser.add_argument(
        "--lib-dir", default="artifacts", metavar="DIR",
        help="Root dir with per-variant artifact subdirs (default: ./artifacts)",
    )
    parser.add_argument(
        "--group", metavar="GROUP",
        choices=["hash", "modern", "encoding", "pqc", "pow"],
        help="Restrict to one KAT group",
    )
    parser.add_argument(
        "--pow", action="store_true",
        help="Enable PoW 1-nonce fastest-path test (default: skip PoW)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true",
    )
    args = parser.parse_args()

    if args.id is not None:
        ids = [args.id]
    elif args.range:
        ids = parse_range(args.range)
        if not ids:
            print(f"ERROR: no variants match range {args.range!r}", file=sys.stderr)
            return 1
    else:
        ids = list(ALL_IDS)

    lib_dir = Path(args.lib_dir)
    if not lib_dir.is_absolute():
        lib_dir = Path.cwd() / lib_dir

    results: list[tuple[int, Variant, int, str]] = []
    for vid in ids:
        if vid not in VARIANTS:
            print(f"WARNING: variant {vid} not in registry, skipping", file=sys.stderr)
            continue
        v = VARIANTS[vid]
        if args.verbose:
            print(f"\n[{v.vid:02d}] {v.tag}")
        rc, status = _run_variant(v, lib_dir, args.group, args.pow, args.verbose)
        results.append((vid, v, rc, status))
        m = _marker(status)
        print(f"  {m}  {vid:02d}  {v.tag:<38}  {status}")

    n_pass  = sum(1 for _, _, _, s in results if s == "PASS")
    n_skip  = sum(1 for _, _, _, s in results if s.startswith("SKIP"))
    n_fail  = sum(1 for _, _, _, s in results if s.startswith("FAIL") or s.startswith("ERROR"))
    n_total = len(results)
    print(f"\n── {n_pass} PASS  {n_skip} SKIP  {n_fail} FAIL  / {n_total} variants ──")

    _write_gha_summary(results)
    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
