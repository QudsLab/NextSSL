"""
build/flatten_hash.py — Flatten hash/ subsystem group dirs.

Lifts all per-algo dirs and _family/ dirs from their intermediate subsystem
group parents (blake/, fast/, legacy/, memory_hard/, skein/, sponge/) directly
under hash/, matching the ALGO.md canonical flat layout.

Also creates missing algo dirs for: keccak256, sha3_512, shake128, shake256,
skein256, skein512, skein1024, kmac128, kmac256, cshake (already exists via
sp800_185/cshake), parallelhash, tuplehash.

Safe to re-run: skips dirs that already exist at destination.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC  = ROOT / "src"
HASH = SRC / "hash"


def move_dir(src: Path, dst: Path) -> None:
    if dst.exists():
        print(f"  SKIP  {dst.relative_to(HASH)} (already exists)")
        return
    if not src.exists():
        print(f"  MISS  {src.relative_to(HASH)} (source missing)")
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(src), str(dst))
    print(f"  MOVE  {src.relative_to(HASH)}  ->  {dst.relative_to(HASH)}")


def create_dir(path: Path) -> None:
    if path.exists():
        print(f"  SKIP  {path.relative_to(HASH)} (already exists)")
        return
    path.mkdir(parents=True)
    print(f"  MKDIR {path.relative_to(HASH)}")


def write_file(path: Path, content: str) -> None:
    if path.exists():
        print(f"  SKIP  {path.relative_to(HASH)} (already exists)")
        return
    path.write_text(content, encoding="utf-8")
    print(f"  WRITE {path.relative_to(HASH)}")


def remove_if_empty(path: Path) -> None:
    if not path.exists():
        return
    remaining = list(path.iterdir())
    if remaining:
        names = [p.name for p in remaining]
        print(f"  KEEP  {path.relative_to(HASH)} (not empty: {names})")
        return
    path.rmdir()
    print(f"  RMDIR {path.relative_to(HASH)}")


def main() -> int:
    print("=== flatten_hash.py ===\n")

    # ── Step 1: lift _family/ dirs ──────────────────────────────────────────
    print("--- family dirs ---")
    move_dir(HASH / "memory_hard/_argon2", HASH / "_argon2")
    move_dir(HASH / "sponge/_keccak",      HASH / "_keccak")
    move_dir(HASH / "skein/_skein",        HASH / "_skein")

    # ── Step 2: lift blake algo dirs ────────────────────────────────────────
    print("\n--- blake ---")
    for algo in ["blake2b", "blake2s", "blake3"]:
        move_dir(HASH / "blake" / algo, HASH / algo)

    # ── Step 3: lift fast algo dirs ─────────────────────────────────────────
    print("\n--- fast ---")
    for algo in ["sha224", "sha256", "sha384", "sha512", "sha512_224", "sha512_256", "sm3"]:
        move_dir(HASH / "fast" / algo, HASH / algo)

    # ── Step 4: lift legacy algo dirs ───────────────────────────────────────
    print("\n--- legacy ---")
    for algo in [
        "has160", "md2", "md4", "md5", "nt",
        "ripemd128", "ripemd160", "ripemd256", "ripemd320",
        "sha0", "sha1", "tiger", "whirlpool",
    ]:
        move_dir(HASH / "legacy" / algo, HASH / algo)

    # ── Step 5: lift memory_hard algo dirs ──────────────────────────────────
    print("\n--- memory_hard ---")
    for algo in [
        "argon2d", "argon2i", "argon2id",
        "balloon", "bcrypt", "catena", "lyra2",
        "makwa", "pomelo", "scrypt", "yescrypt",
    ]:
        move_dir(HASH / "memory_hard" / algo, HASH / algo)

    # ── Step 6: lift sponge algo dirs ───────────────────────────────────────
    print("\n--- sponge ---")
    # sha3 dir becomes sha3_256 (sha3/ = sha3-256 implementation)
    move_dir(HASH / "sponge/sha3",     HASH / "sha3_256")
    move_dir(HASH / "sponge/sha3_224", HASH / "sha3_224")
    move_dir(HASH / "sponge/sha3_384", HASH / "sha3_384")

    # shake: current dir handles both 128 and 256 — lift as shake, then alias
    # The shared shake/ contains shake128_init/shake256_init together.
    # Create shake128/ and shake256/ as the canonical algo dirs; both are thin
    # wrappers over the shared _keccak/ implementation via shake.h.
    move_dir(HASH / "sponge/shake", HASH / "shake")

    # sp800_185 algo dirs
    move_dir(HASH / "sponge/sp800_185/cshake",       HASH / "cshake")
    move_dir(HASH / "sponge/sp800_185/kmac",         HASH / "kmac")
    move_dir(HASH / "sponge/sp800_185/parallelhash", HASH / "parallelhash")
    move_dir(HASH / "sponge/sp800_185/tuplehash",    HASH / "tuplehash")

    # ── Step 7: create missing algo dirs with thin stubs ────────────────────
    print("\n--- create missing ---")

    # keccak256 — thin wrapper over _keccak/keccak.h
    keccak256_dir = HASH / "keccak256"
    create_dir(keccak256_dir)
    write_file(keccak256_dir / "keccak256.h", """\
/* keccak256.h — Keccak-256 (raw Keccak, not SHA-3) */
#ifndef KECCAK256_H
#define KECCAK256_H
#include "keccak.h"
#endif /* KECCAK256_H */
""")
    write_file(keccak256_dir / "keccak256.c", """\
/* keccak256.c — Keccak-256 algo entry point */
#include "keccak256.h"
""")

    # sha3_512 — thin wrapper over _keccak
    sha3_512_dir = HASH / "sha3_512"
    create_dir(sha3_512_dir)
    write_file(sha3_512_dir / "sha3_512.h", """\
/* sha3_512.h — SHA3-512 */
#ifndef SHA3_512_H
#define SHA3_512_H
#include <stdint.h>
#include <stddef.h>
#include "keccak.h"
void sha3_512_hash(const uint8_t *in, size_t inlen, uint8_t out[64]);
#endif /* SHA3_512_H */
""")
    write_file(sha3_512_dir / "sha3_512.c", """\
/* sha3_512.c — SHA3-512 (rate=72, capacity=128, output=64 bytes) */
#include "sha3_512.h"
#include "keccak.h"
#include <string.h>

void sha3_512_hash(const uint8_t *in, size_t inlen, uint8_t out[64]) {
    keccak_hash(in, inlen, out, 64, 72, 0x06);
}
""")

    # shake128 / shake256 — split from the shared shake/ dir
    # shake/ already contains both; create shake128 and shake256 as thin aliases
    shake128_dir = HASH / "shake128"
    shake256_dir = HASH / "shake256"
    create_dir(shake128_dir)
    create_dir(shake256_dir)
    write_file(shake128_dir / "shake128.h", """\
/* shake128.h — SHAKE-128 XOF */
#ifndef SHAKE128_H
#define SHAKE128_H
#include "shake.h"
static inline void shake128_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t len) {
    shake_squeeze(ctx, out, len);
}
#endif /* SHAKE128_H */
""")
    write_file(shake128_dir / "shake128.c", """\
/* shake128.c — SHAKE-128 algo entry (delegates to shared shake/) */
#include "shake128.h"
""")
    write_file(shake256_dir / "shake256.h", """\
/* shake256.h — SHAKE-256 XOF */
#ifndef SHAKE256_H
#define SHAKE256_H
#include "shake.h"
static inline void shake256_squeeze(SHAKE_CTX *ctx, uint8_t *out, size_t len) {
    shake_squeeze(ctx, out, len);
}
#endif /* SHAKE256_H */
""")
    write_file(shake256_dir / "shake256.c", """\
/* shake256.c — SHAKE-256 algo entry (delegates to shared shake/) */
#include "shake256.h"
""")

    # skein256 / skein512 / skein1024 — thin wrappers over _skein/
    for bits in [256, 512, 1024]:
        name = f"skein{bits}"
        d = HASH / name
        create_dir(d)
        write_file(d / f"{name}.h", f"""\
/* {name}.h — Skein-{bits} */
#ifndef {name.upper()}_H
#define {name.upper()}_H
#include "skein.h"
#include "skeinApi.h"
#endif /* {name.upper()}_H */
""")
        write_file(d / f"{name}.c", f"""\
/* {name}.c — Skein-{bits} algo entry point */
#include "{name}.h"
""")

    # kmac128 / kmac256 — split from the shared kmac/ dir
    kmac128_dir = HASH / "kmac128"
    kmac256_dir = HASH / "kmac256"
    create_dir(kmac128_dir)
    create_dir(kmac256_dir)
    write_file(kmac128_dir / "kmac128.h", """\
/* kmac128.h — KMAC-128 */
#ifndef KMAC128_H
#define KMAC128_H
#include "kmac.h"
#endif /* KMAC128_H */
""")
    write_file(kmac128_dir / "kmac128.c", """\
/* kmac128.c — KMAC-128 algo entry */
#include "kmac128.h"
""")
    write_file(kmac256_dir / "kmac256.h", """\
/* kmac256.h — KMAC-256 */
#ifndef KMAC256_H
#define KMAC256_H
#include "kmac.h"
#endif /* KMAC256_H */
""")
    write_file(kmac256_dir / "kmac256.c", """\
/* kmac256.c — KMAC-256 algo entry */
#include "kmac256.h"
""")

    # ── Step 8: clean up now-empty sponge_xof ───────────────────────────────
    print("\n--- cleanup ---")
    # sponge_xof/shake/shake.h is a bridge header — remove it now that shake/
    # is at hash/ level
    sponge_xof_shake_h = HASH / "sponge_xof/shake/shake.h"
    if sponge_xof_shake_h.exists():
        sponge_xof_shake_h.unlink()
        print(f"  DEL   sponge_xof/shake/shake.h (bridge, no longer needed)")
    remove_if_empty(HASH / "sponge_xof/shake")
    remove_if_empty(HASH / "sponge_xof")

    # sp800_185 parent (should be empty after children lifted)
    remove_if_empty(HASH / "sponge/sp800_185")
    remove_if_empty(HASH / "sponge")
    remove_if_empty(HASH / "skein")
    remove_if_empty(HASH / "blake")
    remove_if_empty(HASH / "fast")
    remove_if_empty(HASH / "legacy")
    remove_if_empty(HASH / "memory_hard")

    print("\n=== done ===")
    return 0


if __name__ == "__main__":
    sys.exit(main())
