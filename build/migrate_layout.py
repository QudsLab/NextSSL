#!/usr/bin/env python3
"""
migrate_layout.py — Execute NextSSL modular algorithm layout reorganisation.
Moves ALL algorithm source files into per-algo subfolders, creates _family/
shared-infra directories, and patches every broken relative #include.
Run from the workspace root.
"""

import os
import re
import shutil
from pathlib import Path

ROOT = Path(__file__).parent.parent
SRC  = ROOT / "src"

# ─────────────────────────────────────────────────────────────────
# 1.  FILE MOVES
#     Each entry: (src_relative, dst_relative)  — relative to SRC
# ─────────────────────────────────────────────────────────────────

MOVES = []

def m(src, dst):
    MOVES.append((src, dst))

# ── hash/blake ───────────────────────────────────────────────────
for f in ["blake2b.c", "blake2b.h"]:
    m(f"hash/blake/{f}", f"hash/blake/blake2b/{f}")
for f in ["blake2s.c", "blake2s.h"]:
    m(f"hash/blake/{f}", f"hash/blake/blake2s/{f}")
for f in ["blake3.c","blake3.h","blake3_impl.h","blake3_dispatch.c",
          "blake3_portable.c","blake3_avx2.c","blake3_avx512.c",
          "blake3_sse2.c","blake3_sse41.c"]:
    m(f"hash/blake/{f}", f"hash/blake/blake3/{f}")

# ── hash/fast ────────────────────────────────────────────────────
for f in ["sha224.c","sha224.h"]:
    m(f"hash/fast/{f}", f"hash/fast/sha224/{f}")
for f in ["sha256.c","sha256.h"]:
    m(f"hash/fast/{f}", f"hash/fast/sha256/{f}")
m("hash/fast/sha384.h",     "hash/fast/sha384/sha384.h")
for f in ["sha512.c","sha512.h"]:
    m(f"hash/fast/{f}", f"hash/fast/sha512/{f}")
for f in ["sha512_224.c","sha512_224.h"]:
    m(f"hash/fast/{f}", f"hash/fast/sha512_224/{f}")
for f in ["sha512_256.c","sha512_256.h"]:
    m(f"hash/fast/{f}", f"hash/fast/sha512_256/{f}")

# ── hash/legacy ──────────────────────────────────────────────────
_legacy_pairs = [
    ("has160",    ["has160.c","has160.h"]),
    ("md2",       ["md2.c","md2.h"]),
    ("md4",       ["md4.c","md4.h"]),
    ("md5",       ["md5.c","md5.h"]),
    ("nt",        ["nt.c","nt.h"]),
    ("ripemd128", ["ripemd128.c","ripemd128.h"]),
    ("ripemd160", ["ripemd160.c","ripemd160.h"]),
    ("ripemd256", ["ripemd256.c","ripemd256.h"]),
    ("ripemd320", ["ripemd320.c","ripemd320.h"]),
    ("sha0",      ["sha0.c","sha0.h"]),
    ("sha1",      ["sha1.c","sha1.h"]),
    ("tiger",     ["tiger.c","tiger.h","tiger_sbox.c"]),
    ("whirlpool", ["whirlpool.c","whirlpool.h"]),
]
for algo, files in _legacy_pairs:
    for f in files:
        m(f"hash/legacy/{f}", f"hash/legacy/{algo}/{f}")

# ── hash/memory_hard — argon2 shared infra ───────────────────────
_argon2_shared = [
    "argon2.c","argon2.h","argon2_encoding.c","argon2_encoding.h",
    "blake2-impl.h","blake2.h","blake2b.c",
    "blamka-round-opt.h","blamka-round-ref.h",
    "core.c","core.h","opt.c","ref.c","thread.c","thread.h",
]
for f in _argon2_shared:
    m(f"hash/memory_hard/{f}", f"hash/memory_hard/_argon2/{f}")

for f in ["argon2d.c","argon2d.h"]:
    m(f"hash/memory_hard/{f}", f"hash/memory_hard/argon2d/{f}")
for f in ["argon2i.c","argon2i.h"]:
    m(f"hash/memory_hard/{f}", f"hash/memory_hard/argon2i/{f}")
for f in ["argon2id.c","argon2id.h"]:
    m(f"hash/memory_hard/{f}", f"hash/memory_hard/argon2id/{f}")

# ── hash/skein ───────────────────────────────────────────────────
_skein_files = [
    "skein.c","skein.h","skein_block.c","skeinApi.c","skeinApi.h",
    "threefishApi.c","threefishApi.h",
    "threefish256Block.c","threefish512Block.c","threefish1024Block.c",
    "brg_endian.h","brg_types.h","skein_iv.h","skein_port.h",
    "skein_ops.c","skeinBlockNo3F.c",
]
for f in _skein_files:
    m(f"hash/skein/{f}", f"hash/skein/_skein/{f}")

# ── hash/sponge ──────────────────────────────────────────────────
for f in ["keccak.c","keccak.h"]:
    m(f"hash/sponge/{f}", f"hash/sponge/_keccak/{f}")
for f in ["sha3.c","sha3.h"]:
    m(f"hash/sponge/{f}", f"hash/sponge/sha3/{f}")
for f in ["sha3_224.c","sha3_224.h"]:
    m(f"hash/sponge/{f}", f"hash/sponge/sha3_224/{f}")
for f in ["sha3_384.c","sha3_384.h"]:
    m(f"hash/sponge/{f}", f"hash/sponge/sha3_384/{f}")
for f in ["shake.c","shake.h"]:
    m(f"hash/sponge/{f}", f"hash/sponge/shake/{f}")

for f in ["cshake.c","cshake.h"]:
    m(f"hash/sponge/sp800_185/{f}", f"hash/sponge/sp800_185/cshake/{f}")
for f in ["kmac.c","kmac.h"]:
    m(f"hash/sponge/sp800_185/{f}", f"hash/sponge/sp800_185/kmac/{f}")
for f in ["parallelhash.c","parallelhash.h"]:
    m(f"hash/sponge/sp800_185/{f}", f"hash/sponge/sp800_185/parallelhash/{f}")
for f in ["tuplehash.c","tuplehash.h"]:
    m(f"hash/sponge/sp800_185/{f}", f"hash/sponge/sp800_185/tuplehash/{f}")

# ── modern/symmetric ─────────────────────────────────────────────
for f in ["aes_core.c","aes_internal.h","aes_common.h"]:
    m(f"modern/symmetric/{f}", f"modern/symmetric/_aes/{f}")

_sym_algos = [
    ("aes_cbc",    ["aes_cbc.c","aes_cbc.h"]),
    ("aes_cbc_cs", ["aes_cbc_cs.c","aes_cbc_cs.h"]),
    ("aes_cfb",    ["aes_cfb.c","aes_cfb.h"]),
    ("aes_ctr",    ["aes_ctr.c","aes_ctr.h"]),
    ("aes_ecb",    ["aes_ecb.c","aes_ecb.h"]),
    ("aes_fpe",    ["aes_fpe.c","aes_fpe.h","aes_fpe_alphabets.h"]),
    ("aes_kw",     ["aes_kw.c","aes_kw.h"]),
    ("aes_ofb",    ["aes_ofb.c","aes_ofb.h"]),
    ("aes_xpn",    ["aes_xpn.c","aes_xpn.h"]),
    ("aes_xts",    ["aes_xts.c","aes_xts.h"]),
    ("chacha20",   ["chacha20.c","chacha20.h"]),
    ("three_des",  ["three_des.c","three_des.h"]),
]
for algo, files in _sym_algos:
    for f in files:
        m(f"modern/symmetric/{f}", f"modern/symmetric/{algo}/{f}")

# ── modern/aead ──────────────────────────────────────────────────
for f in ["monocypher.c","monocypher.h","monocypher-ed25519.c","monocypher-ed25519.h"]:
    m(f"modern/aead/{f}", f"modern/aead/_monocypher/{f}")

_aead_algos = [
    ("aes_ccm",          ["aes_ccm.c","aes_ccm.h"]),
    ("aes_eax",          ["aes_eax.c","aes_eax.h"]),
    ("aes_gcm",          ["aes_gcm.c","aes_gcm.h"]),
    ("aes_gcm_siv",      ["aes_gcm_siv.c","aes_gcm_siv.h"]),
    ("aes_gmac",         ["aes_gmac.c","aes_gmac.h"]),
    ("aes_ocb",          ["aes_ocb.c","aes_ocb.h"]),
    ("aes_poly1305",     ["aes_poly1305.c","aes_poly1305.h"]),
    ("aes_siv",          ["aes_siv.c","aes_siv.h"]),
    ("chacha20_poly1305",["chacha20_poly1305.c","chacha20_poly1305.h"]),
]
for algo, files in _aead_algos:
    for f in files:
        m(f"modern/aead/{f}", f"modern/aead/{algo}/{f}")

# ascon — already inside aead/ascon/, sub-divide it
for f in ["ascon_core.c","ascon_core.h"]:
    m(f"modern/aead/ascon/{f}", f"modern/aead/ascon/_ascon/{f}")
for f in ["ascon_aead128.c","ascon_aead128.h"]:
    m(f"modern/aead/ascon/{f}", f"modern/aead/ascon/aead128/{f}")
for f in ["ascon_hash256.c","ascon_hash256.h"]:
    m(f"modern/aead/ascon/{f}", f"modern/aead/ascon/hash256/{f}")
for f in ["ascon_xof128.c","ascon_xof128.h"]:
    m(f"modern/aead/ascon/{f}", f"modern/aead/ascon/xof128/{f}")
for f in ["ascon_cxof128.c","ascon_cxof128.h"]:
    m(f"modern/aead/ascon/{f}", f"modern/aead/ascon/cxof128/{f}")

# ── modern/mac ───────────────────────────────────────────────────
_mac_algos = [
    ("aes_cmac", ["aes_cmac.c","aes_cmac.h"]),
    ("hmac",     ["hmac.c","hmac.h"]),
    ("poly1305", ["poly1305.c","poly1305.h"]),
    ("siphash",  ["siphash.c","siphash.h"]),
]
for algo, files in _mac_algos:
    for f in files:
        m(f"modern/mac/{f}", f"modern/mac/{algo}/{f}")

# ── modern/kdf ───────────────────────────────────────────────────
for f in ["hkdf.c","hkdf.h"]:
    m(f"modern/kdf/{f}", f"modern/kdf/hkdf/{f}")
for f in ["pbkdf2.c","pbkdf2.h"]:
    m(f"modern/kdf/{f}", f"modern/kdf/pbkdf2/{f}")

# ── modern/asymmetric — ed25519/_ed25519 shared + ed25519 public ─
_ed25519_shared = [
    "fe.c","fe.h","ge.c","ge.h","sc.c","sc.h",
    "sha512.c","sha512.h","precomp_data.h","fixedint.h",
    "add_scalar.c","keypair.c","sign.c","verify.c","seed.c",
    "ed25519.h","key_exchange.c",
]
for f in _ed25519_shared:
    m(f"modern/asymmetric/{f}", f"modern/asymmetric/_ed25519/{f}")

# wolf_shim + micro_ecc → _nist_ecc (move entire micro_ecc subtree separately)
m("modern/asymmetric/wolf_shim.h", "modern/asymmetric/_nist_ecc/wolf_shim.h")

_nist_algos = [
    ("p256", ["p256.c","p256.h"]),
    ("p384", ["p384.c","p384.h"]),
    ("p521", ["p521.c","p521.h"]),
    ("det_ecdsa", ["det_ecdsa.c","det_ecdsa.h"]),
    ("dsa",       ["dsa.c","dsa.h"]),
]
for algo, files in _nist_algos:
    for f in files:
        m(f"modern/asymmetric/{f}", f"modern/asymmetric/{algo}/{f}")

# ─────────────────────────────────────────────────────────────────
# 2.  INCLUDE PATCHES
#     Each entry: (file_path_relative_to_SRC, old_include, new_include)
# ─────────────────────────────────────────────────────────────────

PATCHES = []

def p(path, old, new):
    PATCHES.append((path, old, new))

# ── AEAD files: cross-subsystem relative → flat ──────────────────
_aead_files_aes_internal = [
    "modern/aead/aes_gcm/aes_gcm.c",
    "modern/aead/aes_ccm/aes_ccm.c",
    "modern/aead/aes_gcm_siv/aes_gcm_siv.c",
    "modern/aead/aes_eax/aes_eax.c",
    "modern/aead/aes_siv/aes_siv.c",
    "modern/aead/aes_ocb/aes_ocb.c",
    "modern/aead/aes_poly1305/aes_poly1305.c",
]
for f in _aead_files_aes_internal:
    p(f, '"../symmetric/aes_internal.h"', '"aes_internal.h"')

_aead_files_aes_ctr = [
    "modern/aead/aes_gcm/aes_gcm.c",
    "modern/aead/aes_ccm/aes_ccm.c",
    "modern/aead/aes_gcm_siv/aes_gcm_siv.c",
    "modern/aead/aes_eax/aes_eax.c",
    "modern/aead/aes_siv/aes_siv.c",
]
for f in _aead_files_aes_ctr:
    p(f, '"../symmetric/aes_ctr.h"', '"aes_ctr.h"')

# ── symmetric: relative → flat ───────────────────────────────────
p("modern/symmetric/three_des/three_des.c",
  '"../../common/secure_zero.h"', '"secure_zero.h"')
p("modern/symmetric/chacha20/chacha20.c",
  '"../aead/monocypher.h"', '"monocypher.h"')

# ── mac: relative → flat ─────────────────────────────────────────
p("modern/mac/poly1305/poly1305.c",
  '"../aead/monocypher.h"', '"monocypher.h"')
p("modern/mac/hmac/hmac.h",
  '"../../hash/interface/hash_ops.h"', '"hash_ops.h"')
p("modern/mac/hmac/hmac.h",
  '"../../hash/adapters/hash_adapter.h"', '"hash_adapter.h"')
p("modern/mac/hmac/hmac.c",
  '"../../common/secure_zero.h"', '"secure_zero.h"')
p("modern/mac/hmac/hmac.c",
  '"../../hash/adapters/hash_adapter.h"', '"hash_adapter.h"')

# ── asymmetric: relative → flat ──────────────────────────────────
p("modern/asymmetric/det_ecdsa/det_ecdsa.c",
  '"../../modern/mac/hmac.h"', '"hmac.h"')
p("modern/asymmetric/det_ecdsa/det_ecdsa.c",
  '"../../hash/interface/hash_ops.h"', '"hash_ops.h"')
p("modern/asymmetric/p256/p256.c",
  '"../../seed/random/seed_derive_random.h"', '"seed_derive_random.h"')
p("modern/asymmetric/p256/p256.c",
  '"../../seed/drbg/drbg.h"', '"drbg.h"')
p("modern/asymmetric/p256/p256.c",
  '"../../common/secure_zero.h"', '"secure_zero.h"')
p("modern/asymmetric/_ed25519/seed.c",
  '"../../../seed/rng/rng.h"', '"rng.h"')

# ── asymmetric: update ed25519 stub headers (not moved, in modern/ed25519/) ──
p("modern/ed25519/fe.h", '"../asymmetric/fe.h"', '"fe.h"')
p("modern/ed25519/ge.h", '"../asymmetric/ge.h"', '"ge.h"')
p("modern/ed25519/sc.h", '"../asymmetric/sc.h"', '"sc.h"')

# ── hash adapters: reference headers that moved to _argon2/ ──────
p("hash/adapters/argon2_adapter.c",
  '"../memory_hard/argon2.h"', '"argon2.h"')
p("hash/adapters/argon2i_adapter.c",
  '"../memory_hard/argon2i.h"', '"argon2i.h"')
p("hash/adapters/argon2id_adapter.c",
  '"../memory_hard/argon2id.h"', '"argon2id.h"')

# ─────────────────────────────────────────────────────────────────
# 3.  Execute moves
# ─────────────────────────────────────────────────────────────────

def do_moves():
    moved = skipped = errors = 0
    for src_rel, dst_rel in MOVES:
        src = SRC / src_rel
        dst = SRC / dst_rel
        if not src.exists():
            print(f"  SKIP (missing): {src_rel}")
            skipped += 1
            continue
        if dst.exists():
            print(f"  SKIP (exists):  {dst_rel}")
            skipped += 1
            continue
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        print(f"  MOVE: {src_rel}")
        print(f"     -> {dst_rel}")
        moved += 1
    print(f"\n  Moved: {moved}  Skipped: {skipped}  Errors: {errors}")

# ─────────────────────────────────────────────────────────────────
# 4.  Move micro_ecc subtree
# ─────────────────────────────────────────────────────────────────

def move_micro_ecc():
    src = SRC / "modern/asymmetric/micro_ecc"
    dst = SRC / "modern/asymmetric/_nist_ecc/micro_ecc"
    if src.exists() and not dst.exists():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        print(f"  MOVE: modern/asymmetric/micro_ecc -> modern/asymmetric/_nist_ecc/micro_ecc")
    elif not src.exists():
        print(f"  SKIP (missing): micro_ecc")
    else:
        print(f"  SKIP (exists):  _nist_ecc/micro_ecc")

# ─────────────────────────────────────────────────────────────────
# 5.  Execute include patches
# ─────────────────────────────────────────────────────────────────

def do_patches():
    patched = skipped = not_found = 0
    for path_rel, old_inc, new_inc in PATCHES:
        path = SRC / path_rel
        if not path.exists():
            print(f"  PATCH MISSING: {path_rel}")
            not_found += 1
            continue
        text = path.read_text(encoding="utf-8")
        old_line = f"#include {old_inc}"
        new_line = f"#include {new_inc}"
        if old_line not in text:
            if new_line in text:
                print(f"  PATCH ALREADY DONE: {path_rel}  {old_inc}")
                skipped += 1
            else:
                print(f"  PATCH NOT FOUND:    {path_rel}  {old_inc}")
                not_found += 1
            continue
        text = text.replace(old_line, new_line, 1)
        path.write_text(text, encoding="utf-8")
        print(f"  PATCH: {path_rel}")
        print(f"         {old_inc} -> {new_inc}")
        patched += 1
    print(f"\n  Patched: {patched}  Skipped: {skipped}  Not-found: {not_found}")

# ─────────────────────────────────────────────────────────────────
# 6.  Main
# ─────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("NextSSL layout migration")
    print("=" * 70)

    print("\n[1/3] Moving files...")
    do_moves()

    print("\n[2/3] Moving micro_ecc subtree...")
    move_micro_ecc()

    print("\n[3/3] Patching #includes...")
    do_patches()

    print("\nDone. Run: python build/check_layout.py")

if __name__ == "__main__":
    main()
