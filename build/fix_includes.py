#!/usr/bin/env python3
"""
fix_includes.py — Fix all broken #include paths left by migrate_layout.py.
Files outside the migrated set still use old relative paths to headers that
have moved into per-algo subfolders.  Since CMakeLists.txt now exposes every
new subfolder as an include directory, we just convert broken relative paths
to flat filename-only includes.
"""
from pathlib import Path

ROOT = Path(__file__).parent.parent
SRC  = ROOT / "src"

# ─────────────────────────────────────────────────────────────────
# Patch table: (file_relative_to_SRC, old_include_text, new_include_text)
# ─────────────────────────────────────────────────────────────────
PATCHES = []
def p(path, old, new):
    PATCHES.append((path, f'#include {old}', f'#include {new}'))

# ── encoding ─────────────────────────────────────────────────────
p("encoding/base58check.c",         '"../hash/fast/sha256.h"',         '"sha256.h"')
p("encoding/ff70.c",                '"../hash/blake/blake3.h"',        '"blake3.h"')

# ── hash/adapters ────────────────────────────────────────────────
p("hash/adapters/kdf_adapters.h",   '"../memory_hard/argon2.h"',       '"argon2.h"')
p("hash/adapters/argon2d_adapter.c",'"../memory_hard/argon2d.h"',      '"argon2d.h"')
# argon2i_adapter.c and argon2id_adapter.c were already patched in migrate_layout.py

# ── hash/interface/hash_registry.c ───────────────────────────────
r = "hash/interface/hash_registry.c"
p(r, '"../fast/sha224.h"',          '"sha224.h"')
p(r, '"../fast/sha256.h"',          '"sha256.h"')
p(r, '"../fast/sha384.h"',          '"sha384.h"')
p(r, '"../fast/sha512.h"',          '"sha512.h"')
p(r, '"../fast/sha512_224.h"',      '"sha512_224.h"')
p(r, '"../fast/sha512_256.h"',      '"sha512_256.h"')
p(r, '"../blake/blake2b.h"',        '"blake2b.h"')
p(r, '"../blake/blake2s.h"',        '"blake2s.h"')
p(r, '"../blake/blake3.h"',         '"blake3.h"')
p(r, '"../sponge/sha3_224.h"',      '"sha3_224.h"')
p(r, '"../sponge/sha3.h"',          '"sha3.h"')
p(r, '"../sponge/sha3_384.h"',      '"sha3_384.h"')
p(r, '"../sponge/shake.h"',         '"shake.h"')
p(r, '"../memory_hard/argon2.h"',   '"argon2.h"')
p(r, '"../memory_hard/argon2id.h"', '"argon2id.h"')
p(r, '"../memory_hard/argon2i.h"',  '"argon2i.h"')
p(r, '"../memory_hard/argon2d.h"',  '"argon2d.h"')
p(r, '"../legacy/sha1.h"',          '"sha1.h"')
p(r, '"../legacy/sha0.h"',          '"sha0.h"')
p(r, '"../legacy/md5.h"',           '"md5.h"')
p(r, '"../legacy/md4.h"',           '"md4.h"')
p(r, '"../legacy/md2.h"',           '"md2.h"')
p(r, '"../legacy/nt.h"',            '"nt.h"')
p(r, '"../legacy/tiger.h"',         '"tiger.h"')
p(r, '"../legacy/ripemd128.h"',     '"ripemd128.h"')
p(r, '"../legacy/ripemd160.h"',     '"ripemd160.h"')
p(r, '"../legacy/ripemd256.h"',     '"ripemd256.h"')
p(r, '"../legacy/ripemd320.h"',     '"ripemd320.h"')
p(r, '"../legacy/whirlpool.h"',     '"whirlpool.h"')
p(r, '"../legacy/has160.h"',        '"has160.h"')
p(r, '"../sponge/sp800_185/kmac.h"','"kmac.h"')

# ── hash/memory_hard ─────────────────────────────────────────────
p("hash/memory_hard/balloon/balloon_openssl_compat.c", '"../../fast/sha256.h"', '"sha256.h"')
p("hash/memory_hard/makwa/makwa.c",                    '"../../fast/sha256.h"', '"sha256.h"')

# ── hash/record/lms ──────────────────────────────────────────────
p("hash/record/lms/lmots.c", '"../../../hash/fast/sha256.h"', '"sha256.h"')
p("hash/record/lms/lms.c",   '"../../../hash/fast/sha256.h"', '"sha256.h"')

# ── hash/skein/_skein ────────────────────────────────────────────
p("hash/skein/_skein/skein_ops.c", '"../interface/hash_registry.h"', '"hash_registry.h"')

# ── hash/sponge/sp800_185 ────────────────────────────────────────
p("hash/sponge/sp800_185/cshake/cshake.h", '"../shake.h"', '"shake.h"')
p("hash/sponge/sp800_185/kmac/kmac.h",     '"../shake.h"', '"shake.h"')

# ── hash/sponge_xof ──────────────────────────────────────────────
p("hash/sponge_xof/shake/shake.h", '"../../sponge/shake.h"', '"shake.h"')

# ── seed/drbg ────────────────────────────────────────────────────
p("seed/drbg/drbg.h", '"../../hash/fast/sha256.h"', '"sha256.h"')

# ── modern/base_encryption.c ─────────────────────────────────────
p("modern/base_encryption.c", '"symmetric/aes_common.h"', '"aes_common.h"')

# ── modern/aead — .h files with aes_internal.h ───────────────────
p("modern/aead/aes_poly1305/aes_poly1305.h", '"../symmetric/aes_internal.h"', '"aes_internal.h"')
p("modern/aead/aes_siv/aes_siv.h",           '"../symmetric/aes_internal.h"', '"aes_internal.h"')

# ── modern/mac/aes_cmac ──────────────────────────────────────────
p("modern/mac/aes_cmac/aes_cmac.c", '"../symmetric/aes_internal.h"', '"aes_internal.h"')
p("modern/mac/aes_cmac/aes_cmac.h", '"../symmetric/aes_internal.h"', '"aes_internal.h"')

# ── modern/kdf ───────────────────────────────────────────────────
p("modern/kdf/hkdf/hkdf.c",   '"../mac/hmac.h"', '"hmac.h"')   # occurs twice — loop handles both
p("modern/kdf/pbkdf2/pbkdf2.c", '"../mac/hmac.h"', '"hmac.h"')

# ── modern/asymmetric/curve448 — wolf_shim.h ─────────────────────
for f in ["curve448.c","curve448.h","ed448.c","ed448.h",
          "fe_448.c","fe_448.h","ge_448.c","ge_448.h"]:
    p(f"modern/asymmetric/curve448/{f}", '"../wolf_shim.h"', '"wolf_shim.h"')

# ── modern/asymmetric/_nist_ecc/wolf_shim.h ──────────────────────
p("modern/asymmetric/_nist_ecc/wolf_shim.h",
  '"../../seed/random/entropy.h"',         '"entropy.h"')
p("modern/asymmetric/_nist_ecc/wolf_shim.h",
  '"../../hash/sponge_xof/shake/shake.h"', '"shake.h"')

# ── root/hash/root_hash.c ────────────────────────────────────────
p("root/hash/root_hash.c", '"../../hash/blake/blake2b.h"',   '"blake2b.h"')
p("root/hash/root_hash.c", '"../../hash/skein/skeinApi.h"',  '"skeinApi.h"')
p("root/hash/root_hash.c", '"../../hash/sponge/shake.h"',    '"shake.h"')

# ── root/modern/root_modern.c — bulk include update ──────────────
rm = "root/modern/root_modern.c"
p(rm, '"../../modern/symmetric/aes_cbc.h"',        '"aes_cbc.h"')
p(rm, '"../../modern/symmetric/aes_ecb.h"',        '"aes_ecb.h"')
p(rm, '"../../modern/symmetric/aes_ctr.h"',        '"aes_ctr.h"')
p(rm, '"../../modern/symmetric/aes_cfb.h"',        '"aes_cfb.h"')
p(rm, '"../../modern/symmetric/aes_ofb.h"',        '"aes_ofb.h"')
p(rm, '"../../modern/symmetric/aes_xts.h"',        '"aes_xts.h"')
p(rm, '"../../modern/symmetric/aes_fpe.h"',        '"aes_fpe.h"')
p(rm, '"../../modern/symmetric/aes_kw.h"',         '"aes_kw.h"')
p(rm, '"../../modern/symmetric/three_des.h"',      '"three_des.h"')
p(rm, '"../../modern/aead/aes_gcm.h"',             '"aes_gcm.h"')
p(rm, '"../../modern/aead/aes_ccm.h"',             '"aes_ccm.h"')
p(rm, '"../../modern/aead/aes_eax.h"',             '"aes_eax.h"')
p(rm, '"../../modern/aead/aes_gcm_siv.h"',         '"aes_gcm_siv.h"')
p(rm, '"../../modern/aead/aes_ocb.h"',             '"aes_ocb.h"')
p(rm, '"../../modern/aead/aes_siv.h"',             '"aes_siv.h"')
p(rm, '"../../modern/aead/chacha20_poly1305.h"',   '"chacha20_poly1305.h"')
p(rm, '"../../modern/symmetric/chacha20.h"',       '"chacha20.h"')
p(rm, '"../../modern/mac/hmac.h"',                 '"hmac.h"')
p(rm, '"../../modern/mac/poly1305.h"',             '"poly1305.h"')
p(rm, '"../../modern/mac/aes_cmac.h"',             '"aes_cmac.h"')
p(rm, '"../../modern/mac/siphash.h"',              '"siphash.h"')
p(rm, '"../../modern/kdf/hkdf.h"',                 '"hkdf.h"')
p(rm, '"../../modern/kdf/pbkdf2.h"',               '"pbkdf2.h"')
p(rm, '"../../modern/aead/monocypher.h"',          '"monocypher.h"')
p(rm, '"../../modern/asymmetric/ed25519.h"',       '"ed25519.h"')
p(rm, '"../../modern/asymmetric/p256.h"',          '"p256.h"')
p(rm, '"../../modern/asymmetric/p384.h"',          '"p384.h"')
p(rm, '"../../modern/asymmetric/p521.h"',          '"p521.h"')
p(rm, '"../../modern/aead/aes_gmac.h"',            '"aes_gmac.h"')
p(rm, '"../../modern/aead/aes_poly1305.h"',        '"aes_poly1305.h"')
p(rm, '"../../modern/symmetric/aes_cbc_cs.h"',     '"aes_cbc_cs.h"')
p(rm, '"../../modern/symmetric/aes_xpn.h"',        '"aes_xpn.h"')
p(rm, '"../../modern/mac/aes_gmac.h"',             '"aes_gmac.h"')

# ── hash/fast/sm3/sm3_ops.c ──────────────────────────────────────
# sm3_ops.c uses "../../interface/hash_registry.h" — sm3 is in fast/sm3/
# (unchanged folder, relative path still valid)

# ─────────────────────────────────────────────────────────────────
# Apply patches
# ─────────────────────────────────────────────────────────────────
def main():
    patched = skipped = not_found = 0
    for path_rel, old_line, new_line in PATCHES:
        path = SRC / path_rel
        if not path.exists():
            print(f"  MISSING FILE: {path_rel}")
            not_found += 1
            continue
        text = path.read_text(encoding="utf-8")
        if old_line not in text:
            if new_line in text:
                skipped += 1
            else:
                print(f"  NOT FOUND in {path_rel}:  {old_line}")
                not_found += 1
            continue
        # Replace ALL occurrences (hkdf.c includes hmac.h twice)
        count = text.count(old_line)
        text = text.replace(old_line, new_line)
        path.write_text(text, encoding="utf-8")
        print(f"  PATCH({count}x): {path_rel}")
        print(f"                  {old_line} -> {new_line}")
        patched += count

    print(f"\n  Patched occurrences : {patched}")
    print(f"  Already done        : {skipped}")
    print(f"  Not found / missing : {not_found}")

if __name__ == "__main__":
    main()
