#!/usr/bin/env python3
"""check_exports.py — audit NEXTSSL_API declaration ↔ implementation coverage.

Usage:
    python build/check_exports.py          # run from project root
    python build/check_exports.py --json   # machine-readable output

Runs with plain Python 3.8+ and stdlib only. No virtual environment is required.
"""
import argparse
import json
import re
import sys
from pathlib import Path

# Allow running from project root or from build/
sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import ROOT_DIR, PQC_MAIN, POW_API
from helpers.c_parser import (
    extract_api_declarations,
    extract_wrapper_definitions,
    extract_pqc_exports,
    extract_pow_api,
)


def main():
    parser = argparse.ArgumentParser(description="NextSSL export audit")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    # 1.  All NEXTSSL_API declarations in root/ headers
    decls = extract_api_declarations(ROOT_DIR)
    decl_names = {name for _, name in decls}

    # 2.  All nextssl_* function definitions in root/ .c files
    defs = extract_wrapper_definitions(ROOT_DIR)
    def_names = {name for _, name in defs}

    # 3.  All EXPORT functions in pqc_main.c
    pqc_exports = extract_pqc_exports(PQC_MAIN) if PQC_MAIN.exists() else []
    pqc_set = set(pqc_exports)

    # 4.  All NEXTSSL_API in pow_api.c
    pow_exports = extract_pow_api(POW_API) if POW_API.exists() else []
    pow_set = set(pow_exports)

    # Combine all implementations
    all_impl = def_names | pow_set

    # ------- Analysis --------------------------------------------------------
    # A.  Declared but no implementation
    declared_no_impl = decl_names - all_impl
    # B.  Implemented but no declaration (shouldn't happen in root wrappers)
    impl_no_decl = all_impl - decl_names
    # C.  pqc_main.c exports that have no nextssl_ wrapper
    #     Expected mapper:  pqc_foo  →  nextssl_pqc_foo
    # Build SPHINCS+ compressed→readable name map
    # pqc_sphincssha2128fsimple_sign → nextssl_pqc_sphincs_sha2_128f_sign
    def _sphincs_to_readable(compressed: str) -> str:
        """Convert compressed SPHINCS+ pqc_ name to nextssl_ readable name."""
        s = compressed
        if not s.startswith("pqc_sphincs"):
            return ""
        s = s[len("pqc_sphincs"):]  # e.g. "sha2128fsimple_sign"
        # Extract hash family
        if s.startswith("sha2"):
            family = "sha2"
            s = s[4:]
        elif s.startswith("shake"):
            family = "shake"
            s = s[5:]
        else:
            return ""
        # Extract security level + speed (e.g. "128f", "256s")
        m = re.match(r'(\d+)([fs])', s)
        if not m:
            return ""
        level = m.group(1)
        speed = m.group(2)
        s = s[m.end():]
        # Remove "simple" prefix
        if s.startswith("simple"):
            s = s[6:]
        # s is now e.g. "_sign" or "_keypair_derand"
        op = s  # includes leading underscore
        return f"nextssl_pqc_sphincs_{family}_{level}{speed}{op}"

    pqc_unwrapped = []
    for fn in sorted(pqc_set):
        direct = "nextssl_" + fn
        if direct in decl_names:
            continue
        # Check SPHINCS+ readable-name matching
        if "sphincs" in fn:
            readable = _sphincs_to_readable(fn)
            if readable and readable in decl_names:
                continue
        pqc_unwrapped.append(fn)

    if args.json:
        result = {
            "total_declarations": len(decl_names),
            "total_implementations": len(all_impl),
            "declared_no_impl": sorted(declared_no_impl),
            "impl_no_decl": sorted(impl_no_decl),
            "pqc_unwrapped": pqc_unwrapped,
            "match_count": len(decl_names & all_impl),
        }
        print(json.dumps(result, indent=2))
    else:
        print("=" * 60)
        print("  NEXTSSL EXPORT AUDIT")
        print("=" * 60)
        print()
        matched = decl_names & all_impl
        print(f"  Total root-declared functions : {len(decl_names)}")
        print(f"  Total implementations found   : {len(all_impl)}")
        print(f"  Matched (decl + impl)         : {len(matched)}")
        print()

        if declared_no_impl:
            print(f"  ⚠️  {len(declared_no_impl)} declared but NO implementation:")
            for fn in sorted(declared_no_impl):
                print(f"     - {fn}")
            print()

        if impl_no_decl:
            print(f"  ⚠️  {len(impl_no_decl)} implemented but NO declaration:")
            for fn in sorted(impl_no_decl):
                print(f"     - {fn}")
            print()

        if pqc_unwrapped:
            print(f"  ⚠️  {len(pqc_unwrapped)} pqc_main.c EXPORT functions with no direct root wrapper:")
            for fn in pqc_unwrapped:
                print(f"     - {fn}")
            print()

        if not declared_no_impl and not pqc_unwrapped:
            print("  ✅ All declarations have matching implementations.")
            print("  ✅ All pqc_main.c exports have root wrappers.")
        print()

    # Exit code: 0 if clean, 1 if mismatches
    sys.exit(1 if declared_no_impl else 0)


if __name__ == "__main__":
    main()
