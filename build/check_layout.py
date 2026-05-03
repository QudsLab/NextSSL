#!/usr/bin/env python3
"""
tree_analysis.py — NextSSL algorithm layout analysis tool
Reads ALGO.md, maps every algorithm to its proposed folder structure,
cross-references existing src/ layout, and writes full report to tree_report.txt
"""

import os
import re
from pathlib import Path

ROOT = Path(__file__).parent

# ─────────────────────────────────────────────────────────────────
# 1.  Algorithm inventory (from ALGO.md, structured)
# ─────────────────────────────────────────────────────────────────

HASH_ALGOS = [
    # (canonical_name, family, current_path, proposed_path)
    # Hash gets per-algo subfolders, same rule as modern.
    ("blake2b",      "blake",    "hash/blake",              "hash/blake/blake2b"),
    ("blake2s",      "blake",    "hash/blake",              "hash/blake/blake2s"),
    ("blake3",       "blake",    "hash/blake",              "hash/blake/blake3"),
    ("sha224",       "sha2",     "hash/fast",               "hash/fast/sha224"),
    ("sha256",       "sha2",     "hash/fast",               "hash/fast/sha256"),
    ("sha384",       "sha2",     "hash/fast",               "hash/fast/sha384"),
    ("sha512",       "sha2",     "hash/fast",               "hash/fast/sha512"),
    ("sha512-224",   "sha2",     "hash/fast",               "hash/fast/sha512_224"),
    ("sha512-256",   "sha2",     "hash/fast",               "hash/fast/sha512_256"),
    ("sm3",          "sm3",      "hash/fast/sm3",           "hash/fast/sm3"),
    ("has160",       "legacy",   "hash/legacy",             "hash/legacy/has160"),
    ("md2",          "legacy",   "hash/legacy",             "hash/legacy/md2"),
    ("md4",          "legacy",   "hash/legacy",             "hash/legacy/md4"),
    ("md5",          "legacy",   "hash/legacy",             "hash/legacy/md5"),
    ("nt",           "legacy",   "hash/legacy",             "hash/legacy/nt"),
    ("ripemd128",    "ripemd",   "hash/legacy",             "hash/legacy/ripemd128"),
    ("ripemd160",    "ripemd",   "hash/legacy",             "hash/legacy/ripemd160"),
    ("ripemd256",    "ripemd",   "hash/legacy",             "hash/legacy/ripemd256"),
    ("ripemd320",    "ripemd",   "hash/legacy",             "hash/legacy/ripemd320"),
    ("sha0",         "legacy",   "hash/legacy",             "hash/legacy/sha0"),
    ("sha1",         "legacy",   "hash/legacy",             "hash/legacy/sha1"),
    ("whirlpool",    "legacy",   "hash/legacy",             "hash/legacy/whirlpool"),
    ("argon2d",      "argon2",   "hash/memory_hard",        "hash/memory_hard/argon2d"),
    ("argon2i",      "argon2",   "hash/memory_hard",        "hash/memory_hard/argon2i"),
    ("argon2id",     "argon2",   "hash/memory_hard",        "hash/memory_hard/argon2id"),
    ("bcrypt",       "bcrypt",   "hash/memory_hard/bcrypt", "hash/memory_hard/bcrypt"),
    ("catena",       "catena",   "hash/memory_hard/catena", "hash/memory_hard/catena"),
    ("lyra2",        "lyra2",    "hash/memory_hard/lyra2",  "hash/memory_hard/lyra2"),
    ("scrypt",       "scrypt",   "hash/memory_hard",        "hash/memory_hard/scrypt"),
    ("yescrypt",     "yescrypt", "hash/memory_hard",        "hash/memory_hard/yescrypt"),
    ("balloon",      "balloon",  "hash/memory_hard/balloon","hash/memory_hard/balloon"),
    ("pomelo",       "pomelo",   "hash/memory_hard",        "hash/memory_hard/pomelo"),
    ("makwa",        "makwa",    "hash/memory_hard",        "hash/memory_hard/makwa"),
    ("keccak256",    "keccak",   "hash/sponge",             "hash/sponge/_keccak"),
    ("sha3-224",     "keccak",   "hash/sponge",             "hash/sponge/sha3_224"),
    ("sha3-256",     "keccak",   "hash/sponge",             "hash/sponge/sha3"),
    ("sha3-384",     "keccak",   "hash/sponge",             "hash/sponge/sha3_384"),
    ("sha3-512",     "keccak",   "hash/sponge",             "hash/sponge/sha3"),
    ("shake128",     "keccak",   "hash/sponge",             "hash/sponge/shake"),
    ("shake256",     "keccak",   "hash/sponge",             "hash/sponge/shake"),
    ("skein256",     "skein",    "hash/skein",              "hash/skein/_skein"),
    ("skein512",     "skein",    "hash/skein",              "hash/skein/_skein"),
    ("skein1024",    "skein",    "hash/skein",              "hash/skein/_skein"),
    ("kmac128",      "keccak",   "hash/sponge/sp800_185",   "hash/sponge/sp800_185/kmac"),
    ("kmac256",      "keccak",   "hash/sponge/sp800_185",   "hash/sponge/sp800_185/kmac"),
]

MODERN_ALGOS = [
    # (canonical_name, family, category, current_path, proposed_path_under_src_modern)
    ("aes-cbc",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_cbc"),
    ("aes-cbc-cs",          "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_cbc_cs"),
    ("aes-cfb",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_cfb"),
    ("aes-ctr",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_ctr"),
    ("aes-ecb",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_ecb"),
    ("aes-ofb",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_ofb"),
    ("aes-xts",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_xts"),
    ("aes-fpe",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_fpe"),
    ("aes-kw",              "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_kw"),
    ("aes-xpn",             "aes",       "symmetric",  "modern/symmetric",      "modern/symmetric/aes_xpn"),
    ("3des-cbc",            "3des",      "symmetric",  "modern/symmetric",      "modern/symmetric/three_des"),
    ("chacha20",            "chacha20",  "symmetric",  "modern/symmetric",      "modern/symmetric/chacha20"),
    ("sm4",                 "sm4",       "symmetric",  "modern/symmetric/sm4",  "modern/symmetric/sm4"),
    ("aes-gcm",             "aes",       "aead",       "modern/aead",           "modern/aead/aes_gcm"),
    ("aes-ccm",             "aes",       "aead",       "modern/aead",           "modern/aead/aes_ccm"),
    ("aes-eax",             "aes",       "aead",       "modern/aead",           "modern/aead/aes_eax"),
    ("aes-gcm-siv",         "aes",       "aead",       "modern/aead",           "modern/aead/aes_gcm_siv"),
    ("aes-ocb",             "aes",       "aead",       "modern/aead",           "modern/aead/aes_ocb"),
    ("aes-siv",             "aes",       "aead",       "modern/aead",           "modern/aead/aes_siv"),
    ("aes-gmac",            "aes",       "aead",       "modern/aead",           "modern/aead/aes_gmac"),
    ("aes-poly1305",        "aes",       "aead",       "modern/aead",           "modern/aead/aes_poly1305"),
    ("chacha20-poly1305",   "chacha20",  "aead",       "modern/aead",           "modern/aead/chacha20_poly1305"),
    ("ascon-aead128",       "ascon",     "aead",       "modern/aead/ascon",     "modern/aead/ascon/aead128"),
    ("hmac",                "hmac",      "mac",        "modern/mac",            "modern/mac/hmac"),
    ("poly1305",            "poly1305",  "mac",        "modern/mac",            "modern/mac/poly1305"),
    ("aes-cmac",            "aes",       "mac",        "modern/mac",            "modern/mac/aes_cmac"),
    ("siphash",             "siphash",   "mac",        "modern/mac",            "modern/mac/siphash"),
    ("hkdf",                "hkdf",      "kdf",        "modern/kdf",            "modern/kdf/hkdf"),
    ("pbkdf2",              "pbkdf2",    "kdf",        "modern/kdf",            "modern/kdf/pbkdf2"),
    ("ed25519",             "ed25519",   "asymmetric", "modern/asymmetric",     "modern/asymmetric/_ed25519"),
    ("x25519",              "ed25519",   "asymmetric", "modern/asymmetric",     "modern/asymmetric/_ed25519"),
    ("p-256",               "nist_ecc",  "asymmetric", "modern/asymmetric",     "modern/asymmetric/p256"),
    ("p-384",               "nist_ecc",  "asymmetric", "modern/asymmetric",     "modern/asymmetric/p384"),
    ("p-521",               "nist_ecc",  "asymmetric", "modern/asymmetric",     "modern/asymmetric/p521"),
    ("ed448",               "curve448",  "asymmetric", "modern/asymmetric/curve448", "modern/asymmetric/curve448"),
    ("x448",                "curve448",  "asymmetric", "modern/asymmetric/curve448", "modern/asymmetric/curve448"),
    ("dsa",                 "dsa",       "asymmetric", "modern/asymmetric",     "modern/asymmetric/dsa"),
    ("det-ecdsa",           "nist_ecc",  "asymmetric", "modern/asymmetric",     "modern/asymmetric/det_ecdsa"),
    ("rsa",                 "rsa",       "asymmetric", "modern/asymmetric/rsa", "modern/asymmetric/rsa"),
    ("sm2",                 "sm2",       "asymmetric", "modern/asymmetric/sm2", "modern/asymmetric/sm2"),
]

# ─────────────────────────────────────────────────────────────────
# 2.  Family shared folder map
# ─────────────────────────────────────────────────────────────────

# Hash family shared folders (shared infra used by multiple algos in the family)
HASH_FAMILIES = {
    "sha2":    ("hash/fast/_sha2",              ["sha2_common.h"]),
    "keccak":  ("hash/sponge/_keccak",          ["keccak.c", "keccak.h"]),
    "argon2":  ("hash/memory_hard/_argon2",     ["argon2_core.c", "argon2_core.h", "argon2_encoding.c", "argon2_encoding.h"]),
    "skein":   ("hash/skein/_skein",            ["skein.c", "skein.h", "skeinApi.c", "skeinApi.h", "threefish1024Block.c", "threefish256Block.c", "threefish512Block.c"]),
    "blake":   ("hash/blake/_blake",            []),
    "ripemd":  ("hash/legacy/_ripemd",          []),
    "legacy":  ("hash/legacy/_legacy",          []),
}

MODERN_FAMILIES = {
    "aes":       ("modern/symmetric/_aes",       ["aes_core.c", "aes_internal.h", "aes_common.h"]),
    "chacha20":  ("modern/symmetric/_chacha20",  ["chacha20.c", "chacha20.h"]),
    "ed25519":   ("modern/asymmetric/_ed25519",  ["fe.c", "fe.h", "ge.c", "ge.h", "sc.c", "sc.h",
                                                   "sha512.c", "sha512.h", "precomp_data.h", "add_scalar.c",
                                                   "seed.c", "keypair.c", "sign.c", "verify.c"]),
    "nist_ecc":  ("modern/asymmetric/_nist_ecc", ["wolf_shim.h", "micro_ecc/", "fixedint.h"]),
    "ascon":     ("modern/aead/ascon/_ascon",    ["ascon_core.c", "ascon_core.h"]),
}

# ─────────────────────────────────────────────────────────────────
# 3.  Build the proposed tree as a nested dict
# ─────────────────────────────────────────────────────────────────

def insert(tree, path_parts, value=""):
    node = tree
    for part in path_parts[:-1]:
        node = node.setdefault(part, {})
    node[path_parts[-1]] = value

def build_proposed_tree():
    tree = {}

    # Hash family shared folders
    for family, (fpath, files) in HASH_FAMILIES.items():
        if fpath and files:
            for f in files:
                parts = fpath.split("/") + [f]
                insert(tree, parts)

    # Hash algo folders (per-algo subfolders)
    for name, family, current, proposed in HASH_ALGOS:
        slug = name.replace("-", "_").replace("/", "_")
        parts = proposed.split("/") + [f"{slug}.c"]
        insert(tree, parts)

    # Modern family shared folders
    for family, (fpath, files) in MODERN_FAMILIES.items():
        if fpath:
            for f in files:
                parts = fpath.split("/") + [f]
                insert(tree, parts)

    # Modern algo folders
    for name, family, category, _, proposed in MODERN_ALGOS:
        slug = name.replace("-", "_")
        parts = proposed.split("/") + [f"{slug}.c"]
        insert(tree, parts)

    return tree

# ─────────────────────────────────────────────────────────────────
# 4.  Render tree to string
# ─────────────────────────────────────────────────────────────────

def render_tree(tree, prefix="", lines=None):
    if lines is None:
        lines = []
    items = sorted(tree.items(), key=lambda x: (isinstance(x[1], dict), x[0]))
    for i, (name, subtree) in enumerate(items):
        connector = "└── " if i == len(items) - 1 else "├── "
        lines.append(prefix + connector + name)
        if isinstance(subtree, dict) and subtree:
            extension = "    " if i == len(items) - 1 else "│   "
            render_tree(subtree, prefix + extension, lines)
    return lines

# ─────────────────────────────────────────────────────────────────
# 5.  Cross-reference: current vs proposed
# ─────────────────────────────────────────────────────────────────

def check_existing(src_root):
    rows = []
    rows.append(f"{'ALGORITHM':<22} {'CATEGORY':<12} {'FAMILY':<12} {'CURRENT PATH':<40} {'STATUS'}")
    rows.append("-" * 100)

    move_count = 0
    ok_count   = 0
    missing    = 0

    # Hash — check proposed per-algo subfolder (same logic as modern)
    for name, family, current, proposed in HASH_ALGOS:
        cur_path  = src_root / current
        prop_path = src_root / proposed
        if prop_path.exists():
            status = "OK (in place)"
            ok_count += 1
        elif cur_path.exists():
            status = "NEEDS MOVE"
            move_count += 1
        else:
            status = "MISSING"
            missing += 1
        rows.append(f"{name:<22} {'hash':<12} {family:<12} {current:<40} {status}")

    # Modern — verify proposed subdir exists
    for name, family, category, current, proposed in MODERN_ALGOS:
        cur_path  = src_root / current
        prop_path = src_root / proposed
        if prop_path.exists():
            status = "OK (in place)"
            ok_count += 1
        elif cur_path.exists():
            status = "NEEDS MOVE"
            move_count += 1
        else:
            status = "MISSING"
            missing += 1
        rows.append(f"{name:<22} {category:<12} {family:<12} {current:<40} {status}")

    rows.append("")
    rows.append(f"  Already in place  : {ok_count}")
    rows.append(f"  Needs moving      : {move_count}")
    rows.append(f"  Missing           : {missing}")
    rows.append(f"  Total tracked     : {len(HASH_ALGOS) + len(MODERN_ALGOS)}")
    return rows

# ─────────────────────────────────────────────────────────────────
# 6.  Main
# ─────────────────────────────────────────────────────────────────

def main():
    src_root = ROOT.parent / "src"
    out_path = ROOT.parent / "job" / "tree_report.txt"

    lines = []
    lines.append("=" * 80)
    lines.append("NextSSL Algorithm Layout Analysis")
    lines.append("=" * 80)
    lines.append("")

    # Section A: algorithm counts
    lines.append(f"Hash algorithms   : {len(HASH_ALGOS):>3}  (one subfolder per algo + _family/ shared dirs)")
    lines.append(f"Modern algorithms : {len(MODERN_ALGOS):>3}  (one subfolder per algo + _family/ shared dirs)")
    lines.append("")

    # Section B: proposed tree
    lines.append("─" * 80)
    lines.append("PROPOSED DIRECTORY TREE  (src/hash/  and  src/modern/)")
    lines.append("─" * 80)
    lines.append("src/")
    tree = build_proposed_tree()
    tree_lines = render_tree(tree)
    lines.extend(tree_lines)
    lines.append("")

    # Section C: cross-reference table
    lines.append("─" * 80)
    lines.append("CROSS-REFERENCE: CURRENT vs PROPOSED")
    lines.append("─" * 80)
    lines.extend(check_existing(src_root))
    lines.append("")

    # Section D: family shared folder summary
    lines.append("─" * 80)
    lines.append("FAMILY SHARED FOLDERS (underscore-prefix convention)")
    lines.append("─" * 80)
    all_families = {**HASH_FAMILIES, **MODERN_FAMILIES}
    for family, (fpath, files) in sorted(all_families.items()):
        if fpath:
            lines.append(f"  _  {fpath}/")
            for f in files:
                lines.append(f"       {f}")
    lines.append("")

    # Section E: phase execution order
    lines.append("─" * 80)
    lines.append("EXECUTION PHASES")
    lines.append("─" * 80)
    phases = [
        ("A", "hash/ per-algo subfolders (blake, fast, legacy, memory_hard, sponge, skein)",
             "Move each hash algo into its own subfolder; shared infra into _family/ dirs"),
        ("B", "modern/symmetric/_aes/ + per-mode subfolders",
             "Move aes_core.c/aes_internal.h to _aes/; each AES mode into its own subfolder"),
        ("C", "modern/aead/ per-algo subfolders",
             "Each AEAD algo (aes_gcm, aes_ccm, chacha20_poly1305…) into its own subfolder"),
        ("D", "modern/mac/ per-algo subfolders",
             "hmac/, poly1305/, aes_cmac/, siphash/ subfolders"),
        ("E", "modern/kdf/ per-algo subfolders",
             "hkdf/, pbkdf2/ subfolders"),
        ("F", "modern/asymmetric/_ed25519/ + x25519/ + _nist_ecc/ + p256/p384/p521/",
             "Group Ed25519 shared files; separate x25519; group NIST-ECC shared infra"),
        ("G", "CMakeLists.txt include-dir sweep",
             "Add every new _family/ dir to target_include_directories; build all platforms"),
    ]
    for code, folder, desc in phases:
        lines.append(f"  Phase {code}: {folder}")
        lines.append(f"           {desc}")
    lines.append("")

    text = "\n".join(lines)
    out_path.write_text(text, encoding="utf-8")
    print(f"Written: {out_path}")
    print(f"Lines  : {len(lines)}")

    # Quick summary to stdout
    print(f"\nHash algos   : {len(HASH_ALGOS)}")
    print(f"Modern algos : {len(MODERN_ALGOS)}")
    print(f"Total        : {len(HASH_ALGOS) + len(MODERN_ALGOS)}")

if __name__ == "__main__":
    main()
