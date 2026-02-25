#!/usr/bin/env python3
"""Post-install verification script for NextSSL.

Prints SHA-256 hashes, package metadata, enum counts, and class attributes
as concrete proof that the installation succeeded.

Usage:
    python verify_install.py --version 0.0.8
"""

import argparse
import hashlib
import pathlib
import subprocess
import sys


def verify_version(expected):
    """Check installed version matches expected."""
    import nextssl
    ver = nextssl.__version__
    match = ver == expected
    print(f"Version installed : {ver}  {'OK' if match else 'MISMATCH!'}")
    print(f"Version expected  : {expected}")
    if not match:
        print(f"[FATAL] Version mismatch: got {ver}, expected {expected}")
        sys.exit(1)


def print_file_hashes():
    """Print SHA-256 hashes of every installed .py file."""
    import nextssl
    pkg_dir = pathlib.Path(nextssl.__file__).parent
    print(f"Package location  : {pkg_dir}")
    print()
    print("--- Installed File SHA-256 Hashes ---")
    file_count = 0
    for f in sorted(pkg_dir.rglob("*.py")):
        digest = hashlib.sha256(f.read_bytes()).hexdigest()
        rel = f.relative_to(pkg_dir)
        print(f"  {digest[:16]}...  {rel}")
        file_count += 1
    print(f"Total .py files: {file_count}")
    print()


def print_pip_metadata():
    """Print pip show output."""
    print("--- pip show nextssl ---")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "show", "nextssl"],
        capture_output=True, text=True
    )
    print(result.stdout)


def print_wheel_record():
    """Print wheel RECORD manifest."""
    import nextssl
    pkg_dir = pathlib.Path(nextssl.__file__).parent
    dist_infos = list(pkg_dir.parent.glob("nextssl-*.dist-info"))
    if dist_infos:
        record = dist_infos[0] / "RECORD"
        if record.exists():
            lines = record.read_text().splitlines()
            print("--- RECORD (wheel manifest) first 20 entries ---")
            for line in lines[:20]:
                print(f"  {line}")
            print(f"  ... ({len(lines)} total entries)")
    print()


def verify_imports():
    """Import every module group and print proof."""
    results = []

    try:
        from nextssl import hash, dhcm, pow, pqc, primitives, kdf, encoding, root, unsafe
        modules = [hash, dhcm, pow, pqc, primitives, kdf, encoding, root, unsafe]
        for m in modules:
            h = hashlib.sha256(m.__name__.encode()).hexdigest()[:12]
            results.append(f"  [PASS] {m.__name__:<30}  name_hash={h}  attrs={len(dir(m))}")
    except Exception as e:
        results.append(f"  [FAIL] Core module import: {e}")
        _print_results(results)
        sys.exit(1)

    _try_import(results, "Hash classes",
                "from nextssl import Hash, HashAlgorithm, BLAKE2, SHAKE, Argon2",
                lambda: f"HashAlgorithm_count={_enum_len('nextssl', 'HashAlgorithm')}")

    _try_import(results, "PQC classes",
                "from nextssl import KEM, KEMAlgorithm, Sign, SignAlgorithm",
                lambda: f"KEMAlgorithm_count={_enum_len('nextssl', 'KEMAlgorithm')}  SignAlgorithm_count={_enum_len('nextssl', 'SignAlgorithm')}")

    _try_import(results, "Cipher classes",
                "from nextssl import AES, AESMode, ChaCha20Poly1305",
                lambda: f"AESMode_count={_enum_len('nextssl', 'AESMode')}")

    _try_import(results, "ECC classes",
                "from nextssl import Ed25519, Ed448, Curve25519, Curve448, Ristretto255, Elligator2",
                lambda: "6 classes loaded")

    _try_import(results, "MAC classes",
                "from nextssl import MAC, MACAlgorithm, SipHash",
                lambda: f"MACAlgorithm_count={_enum_len('nextssl', 'MACAlgorithm')}")

    _try_import(results, "KDF classes",
                "from nextssl import HKDF, KDF_SHAKE256, KDFAlgorithm",
                lambda: f"KDFAlgorithm_count={_enum_len('nextssl', 'KDFAlgorithm')}")

    _try_import(results, "Encoding classes",
                "from nextssl import Base64, Hex, FlexFrame70, b64encode, b64decode, hexencode, hexdecode",
                lambda: "7 names loaded")

    _try_import(results, "Root module",
                "import nextssl.root",
                lambda: f"attrs={len(dir(__import__('nextssl.root')))}")

    _try_import(results, "Unsafe module",
                "import nextssl.unsafe",
                lambda: f"attrs={len(dir(__import__('nextssl.unsafe')))}")

    _print_results(results)


def _enum_len(module, name):
    """Get length of an enum class."""
    import importlib
    mod = importlib.import_module(module)
    return len(list(getattr(mod, name)))


def _try_import(results, label, import_stmt, proof_fn):
    """Try an import and append result."""
    try:
        exec(import_stmt)
        proof = proof_fn()
        results.append(f"  [PASS] {label:<30}  {proof}")
    except Exception as e:
        results.append(f"  [FAIL] {label}: {e}")


def _print_results(results):
    """Print results and summary."""
    for r in results:
        print(r)
    fail_count = sum(1 for r in results if "[FAIL]" in r)
    pass_count = sum(1 for r in results if "[PASS]" in r)
    print()
    print(f"Summary: {pass_count} passed, {fail_count} failed")
    if fail_count > 0:
        print("[ERROR] Some imports failed!")
        sys.exit(1)
    print("[PROOF] All module imports verified successfully")


def main():
    parser = argparse.ArgumentParser(description="Verify NextSSL installation")
    parser.add_argument("--version", required=True, help="Expected version string")
    args = parser.parse_args()

    print("=" * 70)
    print("NEXTSSL INSTALLATION VERIFICATION")
    print("=" * 70)

    verify_version(args.version)
    print()
    print_file_hashes()
    print_pip_metadata()
    print_wheel_record()

    print("=" * 70)
    print("MODULE IMPORT VERIFICATION")
    print("=" * 70)
    verify_imports()
    print("=" * 70)


if __name__ == "__main__":
    main()
