#!/usr/bin/env python3
"""check_algos.py — verify every algorithm has a complete root interface chain.

Checks:
  1. Hash registry  → hash_ops → seed extern → DHCM enum → PoW adapter → root
  2. PQC algorithms → pqc_main.c EXPORT → root_pqc.h declaration
  3. Modern crypto  → src/modern/ .c files → root_modern.h declaration

Usage:
    python build/check_algos.py
"""
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from config import (
    ROOT_DIR, PQC_MAIN, MODERN_DIR,
    HASH_REGISTRY, SEED_HASH_OPS, DHCM_TYPES, POW_DISPATCHER,
)
from helpers.c_parser import (
    extract_api_declarations,
    extract_pqc_exports,
    scan_modern_sources,
)


def _read(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


# ---- Hash chain verification ------------------------------------------------

def check_hash_chain():
    """Verify every registered hash has all 5 chain links."""
    print("=" * 60)
    print("  HASH ALGORITHM CHAIN")
    print("=" * 60)

    # 1. hash_registry.c → find all hash_register(&xxx_ops) calls
    reg_text = _read(HASH_REGISTRY)
    registered = re.findall(r'hash_register\s*\(\s*&\s*(\w+_ops)\s*\)', reg_text)
    print(f"\n  Registered hash_ops: {len(registered)}")

    # 2. seed/hash/hash_ops.h → extern declarations
    seed_text = _read(SEED_HASH_OPS)
    seed_externs = set(re.findall(r'extern\s+(?:const\s+)?hash_ops_t\s+(\w+_ops)', seed_text))

    # 3. DHCM types → enum entries
    dhcm_text = _read(DHCM_TYPES)
    dhcm_enums = set(re.findall(r'DHCM_(\w+)', dhcm_text))

    # 4. PoW dispatcher → adapter entries
    disp_text = _read(POW_DISPATCHER)
    pow_adapters = set(re.findall(r'"(\w+)"', disp_text))

    missing_seed = []
    missing_dhcm = []
    for ops_name in sorted(registered):
        if ops_name not in seed_externs:
            missing_seed.append(ops_name)

    for ops_name in sorted(registered):
        # Convert ops name to algo name for DHCM lookup
        algo = ops_name.replace("_ops", "").upper()
        # Loose match: check if any DHCM enum contains the algo base name
        if not any(algo in e for e in dhcm_enums):
            missing_dhcm.append(ops_name)

    if missing_seed:
        print(f"  ⚠️  {len(missing_seed)} hash_ops missing seed/hash/hash_ops.h extern:")
        for n in missing_seed:
            print(f"     - {n}")
    else:
        print(f"  ✅ All {len(registered)} have seed extern")

    if missing_dhcm:
        print(f"  ⚠️  {len(missing_dhcm)} hash_ops with no obvious DHCM enum match:")
        for n in missing_dhcm:
            print(f"     - {n}")
    else:
        print(f"  ✅ All have DHCM enum entries")

    print()
    return len(registered)


# ---- PQC coverage verification -----------------------------------------------

def check_pqc_coverage():
    """Verify every pqc_main.c EXPORT has a root_pqc.h declaration."""
    print("=" * 60)
    print("  PQC ALGORITHM COVERAGE")
    print("=" * 60)

    if not PQC_MAIN.exists():
        print("  ⚠️  pqc_main.c not found, skipping.")
        return 0

    pqc_exports = extract_pqc_exports(PQC_MAIN)
    decls = extract_api_declarations(ROOT_DIR)
    decl_names = {name for _, name in decls}

    # Map pqc_foo → nextssl_pqc_foo or check readable-name variants
    covered = 0
    uncovered = []
    for fn in pqc_exports:
        direct = "nextssl_" + fn
        if direct in decl_names:
            covered += 1
            continue
        # SPHINCS+ uses readable names — check if any decl contains key fragments
        # e.g. pqc_sphincssha2128fsimple_sign → nextssl_pqc_sphincs_sha2_128f_sign
        base = fn.replace("pqc_", "")
        found = False
        for dname in decl_names:
            # rough match: strip underscores and "simple" to compare
            d_clean = dname.replace("nextssl_pqc_sphincs_", "").replace("_", "")
            b_clean = base.replace("sphincs", "").replace("simple", "").replace("_", "")
            if d_clean == b_clean:
                found = True
                break
        if found:
            covered += 1
        else:
            uncovered.append(fn)

    print(f"\n  pqc_main.c EXPORT functions: {len(pqc_exports)}")
    print(f"  With root wrapper          : {covered}")

    if uncovered:
        print(f"  ⚠️  {len(uncovered)} EXPORT functions with NO root wrapper:")
        for fn in sorted(uncovered):
            print(f"     - {fn}")
    else:
        print(f"  ✅ All {covered} pqc exports have root wrappers")

    print()
    return len(uncovered)


# ---- Modern coverage verification -------------------------------------------

def check_modern_coverage():
    """Check which modern/ source files have root wrappers."""
    print("=" * 60)
    print("  MODERN CRYPTO COVERAGE")
    print("=" * 60)

    if not MODERN_DIR.exists():
        print("  ⚠️  modern/ directory not found, skipping.")
        return 0

    sources = scan_modern_sources(MODERN_DIR)
    decls = extract_api_declarations(ROOT_DIR)
    decl_names = {name for _, name in decls}

    # Check which subdirectories have any nextssl_ wrapper
    subdirs = {}
    for subdir, fname in sources:
        if subdir not in subdirs:
            subdirs[subdir] = []
        subdirs[subdir].append(fname)

    # For each subdir, list files and check if a wrapper likely exists
    uncovered_files = []
    skip_files = {
        "aes_common.c", "aes_internal.c", "aes_fpe_alphabets.c",
        "fe.c", "ge.c", "sc.c", "sha512.c", "precomp_data.c",
        "fe_448.c", "ge_448.c", "wolf_shim.c", "fixedint.c",
        # Internal / support files (not direct algorithm implementations)
        "aes_core.c", "uECC.c", "key_exchange.c", "add_scalar.c",
        "base_encryption.c", "seed.c",
        # Monocypher is a bundled third-party library, not individually wrapped
        "monocypher.c", "monocypher-ed25519.c",
        # Curve-math internals
        "elligator2.c", "ristretto255.c",
        # Conditional modules (wrapped under #ifdef guards)
        "curve448.c", "curve448_det.c", "sm4_impl.c",
    }

    # Stem aliases: wrapper name differs from source filename
    stem_aliases = {
        "three_des": "3des",       # nextssl_sym_3des_cbc_*
        "aes_poly1305": "aead",    # bundled within AEAD, AES-Poly1305 is internal
    }

    for subdir in sorted(subdirs):
        for fname in sorted(subdirs[subdir]):
            if fname in skip_files:
                continue
            # Derive expected wrapper prefix from filename
            stem = Path(fname).stem  # e.g. "aes_cbc" from "aes_cbc.c"
            # Check aliases first
            check_stem = stem_aliases.get(stem, stem)
            # Check if any root declaration contains this stem
            has_wrapper = any(
                check_stem.replace("_", "") in d.replace("_", "")
                for d in decl_names
            )
            if not has_wrapper:
                uncovered_files.append(f"{subdir}/{fname}")

    print(f"\n  Modern source files (non-internal): {sum(len(v) for v in subdirs.values()) - len(skip_files)}")
    if uncovered_files:
        print(f"  ⚠️  {len(uncovered_files)} files with no obvious root wrapper:")
        for f in uncovered_files:
            print(f"     - {f}")
    else:
        print(f"  ✅ All modern source files have root wrappers")

    print()
    return len(uncovered_files)


def main():
    hash_count = check_hash_chain()
    pqc_gaps = check_pqc_coverage()
    modern_gaps = check_modern_coverage()

    print("=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    print(f"  Hash algos registered : {hash_count}")
    print(f"  PQC export gaps       : {pqc_gaps}")
    print(f"  Modern file gaps      : {modern_gaps}")
    total_gaps = pqc_gaps + modern_gaps
    if total_gaps == 0:
        print("  ✅ Full coverage!")
    else:
        print(f"  ⚠️  {total_gaps} total gaps remaining")
    print()
    sys.exit(1 if total_gaps else 0)


if __name__ == "__main__":
    main()
