# Test Proposal — Developer Reference

## Overview

This document describes the two-tier test system for NextSSL's 29 build
variants.  The system is designed so that **no issue can be silently missed**:
every variant is either executed with full KAT coverage or verified at the
binary-header level (for targets that cannot execute on the CI runner).

---

## 1. Variant numbering

```
 ID   Platform        Arch            Toolchain  Exec mode
 ──   ──────────      ──────────────  ─────────  ──────────────────────
 11   Windows         x86_64          msvc       native
 12   Windows         x86             msvc       native
 13   Windows         arm64           msvc       pe_check *
 14   Windows         x86_64          mingw      native
 15   Windows         x86             mingw      native
 16   Windows         armv7           msvc       pe_check *

 21   Linux glibc     x86_64          gcc        native
 22   Linux glibc     x86             gcc        qemu_x86
 23   Linux glibc     arm64           gcc        qemu_arm64
 24   Linux glibc     armv7           gcc        qemu_arm
 25   Linux glibc     riscv64         gcc        qemu_riscv64
 26   Linux glibc     s390x           gcc        qemu_s390x
 27   Linux glibc     ppc64le         gcc        qemu_ppc64le
 28   Linux glibc     loongarch64     gcc        qemu_loongarch64

 31   Linux musl      x86_64          gcc        native
 32   Linux musl      arm64           gcc        qemu_arm64
 33   Linux musl      armv7           gcc        qemu_arm

 41   macOS           x86_64          clang      native
 42   macOS           arm64           clang      native
 43   macOS           universal       clang      native

 51   WASM            wasm32          emscripten node_wasm
 52   WASM            wasm32          wasi       wasi_wasm

 61   Android         arm64-v8a       ndk        qemu_arm64
 62   Android         armeabi-v7a     ndk        qemu_arm
 63   Android         x86_64          ndk        native
 64   Android         x86             ndk        qemu_x86

 71   iOS             device-arm64    clang      macho_check *
 72   iOS             sim-arm64       clang      native
 73   iOS             sim-x86_64      clang      macho_check *

* header-only: binary verified but KAT execution is skipped
```

---

## 2. Directory structure

```
test/
  variants.py          ← variant registry (single source of truth)
  │
  ├── mass/            ← TYPE 1: mass smoke test
  │     run_mass.py    ← CLI entry point
  │     header_check.py
  │     smoke_kat.py
  │     __init__.py
  │
  ├── full/            ← TYPE 2: full KAT
  │     run_full.py    ← CLI entry point
  │     __init__.py
  │
  ├── proposal/
  │     SMALL.md       ← quick overview
  │     MEDIUM.md      ← this file
  │     LARGE.md       ← complete spec
  │
  ├── run_tests.py     ← full KAT engine (existing)
  ├── wasm_runner.mjs  ← Emscripten bridge (existing)
  ├── kat/             ← KAT vector data
  └── __init__.py
```

---

## 3. Mass smoke test (`test/mass/`)

**Purpose**: verify every binary at the lowest cost possible.  Fast enough to
run on every push without burning CI minutes.

### Steps (per variant)

1. Locate binary under `artifacts/<id>/` or `artifacts/<artifact-name>/`.
2. Read first 4 bytes → check magic (MZ / ELF / Mach-O / `\0asm` / JS-text).
3. If the variant is natively executable on this host: call
   `nextssl_hash_compute("sha256", "abc")` via ctypes and compare against
   Python `hashlib.sha256(b"abc").digest()`.
4. Print one result line.

### Execution modes

| Mode           | How it runs                          | KAT? |
|----------------|--------------------------------------|------|
| native         | direct ctypes / subprocess           | yes  |
| pe_check       | MZ magic bytes only                  | no   |
| macho_check    | Mach-O magic bytes only              | no   |
| qemu_*         | header checked; KAT needs QEMU env   | host |
| node_wasm      | header checked; KAT via Node.js      | host |
| wasi_wasm      | header checked; KAT via wasmtime     | host |

`host` = KAT is run when the host environment provides the required tool.

### CLI reference

```bash
python test/mass/run_mass.py [OPTIONS]

  -R SPEC, --range SPEC    variant range: "11-28", "61-64", "11,21,31"
  --id VID                 single variant ID
  --lib-dir DIR            artifact root (default: ./artifacts)
  --full                   escalate to full KAT (delegates to run_tests.py)
  -v, --verbose
```

---

## 4. Full KAT (`test/full/`)

**Purpose**: confirm every algorithm produces the correct output for every
test vector in `KAT/data/`.  Delegates to `test/run_tests.py` per variant.

### Algorithms tested

| Group    | Algorithms                                                              |
|----------|-------------------------------------------------------------------------|
| hash     | SHA-256, SHA-512, SHA-384, SHA3-256, SHA3-512, BLAKE2b, BLAKE2s, BLAKE3,|
|          | MD5, SHA-1, Skein-256/512  (memory-hard: Argon2/bcrypt/scrypt → SKIP)  |
| modern   | HMAC-SHA256/SHA512, AES-128/256-CBC, AES-128/256-GCM,                  |
|          | ChaCha20-Poly1305, Poly1305, HKDF, PBKDF2                              |
| encoding | Base64, Hex, Bech32, Base58  (Python stdlib reference, no C call)       |
| pqc      | Structural KAT validation (typed API; execution skipped)                |
| pow      | Skipped by default; `--pow` enables 1-nonce fastest-path test           |

### CLI reference

```bash
python test/full/run_full.py [OPTIONS]

  -R SPEC, --range SPEC    variant range
  --id VID                 single variant ID
  --lib-dir DIR            artifact root (default: ./artifacts)
  --group GROUP            restrict to one group: hash|modern|encoding|pqc|pow
  --pow                    enable PoW 1-nonce test
  -v, --verbose
```

---

## 5. Artifact layout

Both runners expect artifacts to be extracted under a root directory:

```
artifacts/              (default; override with --lib-dir)
  11/  nextssl.dll
  12/  nextssl.dll
  21/  libnextssl.so
  ...
  51/  nextssl.js
       nextssl.wasm     ← Emscripten: JS glue + .wasm side-car
  52/  nextssl.wasm     ← WASI: pure .wasm
  ...
```

The runner also accepts `artifacts/<artifact-name>/` as a fallback so you can
drop CI artifact archives without renaming them.

---

## 6. Range filter (`-R`)

The range spec filters by numeric variant ID:

| Spec      | Variants selected              |
|-----------|-------------------------------|
| `11-16`   | Windows (all 6)                |
| `11-28`   | Windows + Linux glibc (14)     |
| `11-33`   | Windows + Linux (17)           |
| `61-64`   | Android (all 4)                |
| `71-73`   | iOS (all 3)                    |
| `11-73`   | Everything (all 29)            |
| `21,42`   | Specific IDs                   |

---

## 7. CI integration

The existing `test.yml` workflow runs one job per variant (recommended for
parallel CI).  The local runners (`run_mass.py`, `run_full.py`) are designed
for local development and for a future unified CI job that downloads all
artifacts and runs them sequentially.

```yaml
# Example: add a mass-test gate step to an existing job
- name: Mass smoke test (this platform)
  run: python test/mass/run_mass.py -R 21 --lib-dir _art
```

---

## 8. Exit codes

| Code | Meaning                                       |
|------|-----------------------------------------------|
| 0    | all tested variants PASS or SKIP              |
| 1    | at least one FAIL                             |
