# Test Proposal — Complete Specification

## 1. Goals

| Goal | How it is achieved |
|------|--------------------|
| No binary can be silently broken | Every variant produces a `PASS`, `HEADER-ONLY`, or explicit `SKIP` — never silence |
| Cover every algorithm | Full KAT runner uses every vector in `KAT/data/` |
| Cover every architecture | 29 variants across 7 platform groups; cross-arch via QEMU or header check |
| Fast push-gate | Mass runner completes in ~5 s for all 29 (header + 1 KAT each) |
| No virtualenv dependency | Pure `ctypes` + Python stdlib; only optional tools (QEMU, Node, wasmtime) |
| CI-friendly output | `$GITHUB_STEP_SUMMARY` markdown table written automatically |

---

## 2. Variant registry (`test/variants.py`)

The registry is the **single source of truth** for all variant metadata.
Adding a new variant requires only one new `Variant(...)` line.

### Full variant table

| ID | Platform     | Arch           | Toolchain   | Artifact name                          | Binary  | Exec mode           | Runner         |
|----|--------------|----------------|-------------|----------------------------------------|---------|---------------------|----------------|
| 11 | win          | x86_64         | msvc        | nextssl__win__x86_64-msvc              | *.dll   | native              | windows-2022   |
| 12 | win          | x86            | msvc        | nextssl__win__x86-msvc                 | *.dll   | native              | windows-2022   |
| 13 | win          | arm64          | msvc        | nextssl__win__arm64-msvc               | *.dll   | pe_check            | windows-2022   |
| 14 | win          | x86_64         | mingw       | nextssl__win__x86_64-mingw             | *.dll   | native              | windows-2022   |
| 15 | win          | x86            | mingw       | nextssl__win__x86-mingw                | *.dll   | native              | windows-2022   |
| 16 | win          | armv7          | msvc        | nextssl__win__armv7-msvc               | *.dll   | pe_check            | windows-2022   |
| 21 | linux-glibc  | x86_64         | gcc         | nextssl__linux-glibc__x86_64           | *.so    | native              | ubuntu-24.04   |
| 22 | linux-glibc  | x86            | gcc         | nextssl__linux-glibc__x86              | *.so    | qemu_x86            | ubuntu-24.04   |
| 23 | linux-glibc  | arm64          | gcc         | nextssl__linux-glibc__arm64            | *.so    | qemu_arm64          | ubuntu-24.04   |
| 24 | linux-glibc  | armv7          | gcc         | nextssl__linux-glibc__armv7            | *.so    | qemu_arm            | ubuntu-24.04   |
| 25 | linux-glibc  | riscv64        | gcc         | nextssl__linux-glibc__riscv64          | *.so    | qemu_riscv64        | ubuntu-24.04   |
| 26 | linux-glibc  | s390x          | gcc         | nextssl__linux-glibc__s390x            | *.so    | qemu_s390x          | ubuntu-24.04   |
| 27 | linux-glibc  | ppc64le        | gcc         | nextssl__linux-glibc__ppc64le          | *.so    | qemu_ppc64le        | ubuntu-24.04   |
| 28 | linux-glibc  | loongarch64    | gcc         | nextssl__linux-glibc__loongarch64      | *.so    | qemu_loongarch64    | ubuntu-24.04   |
| 31 | linux-musl   | x86_64         | gcc         | nextssl__linux-musl__x86_64            | *.so    | native              | ubuntu-24.04   |
| 32 | linux-musl   | arm64          | gcc         | nextssl__linux-musl__arm64             | *.so    | qemu_arm64          | ubuntu-24.04   |
| 33 | linux-musl   | armv7          | gcc         | nextssl__linux-musl__armv7             | *.so    | qemu_arm            | ubuntu-24.04   |
| 41 | macos        | x86_64         | clang       | nextssl__macos__x86_64                 | *.dylib | native              | macos-14       |
| 42 | macos        | arm64          | clang       | nextssl__macos__arm64                  | *.dylib | native              | macos-14       |
| 43 | macos        | universal      | clang       | nextssl__macos__universal              | *.dylib | native              | macos-14       |
| 51 | wasm         | wasm32         | emscripten  | nextssl__wasm__emscripten-wasm32       | *.js    | node_wasm           | ubuntu-24.04   |
| 52 | wasm         | wasm32         | wasi        | nextssl__wasm__wasi-wasm32             | *.wasm  | wasi_wasm           | ubuntu-24.04   |
| 61 | android      | arm64-v8a      | ndk         | nextssl__android__arm64-v8a            | *.so    | qemu_arm64          | ubuntu-24.04   |
| 62 | android      | armeabi-v7a    | ndk         | nextssl__android__armeabi-v7a          | *.so    | qemu_arm            | ubuntu-24.04   |
| 63 | android      | x86_64         | ndk         | nextssl__android__x86_64               | *.so    | native              | ubuntu-24.04   |
| 64 | android      | x86            | ndk         | nextssl__android__x86                  | *.so    | qemu_x86            | ubuntu-24.04   |
| 71 | ios          | device-arm64   | clang       | nextssl__ios__device-arm64             | *.dylib | macho_check         | macos-14       |
| 72 | ios          | sim-arm64      | clang       | nextssl__ios__sim-arm64                | *.dylib | native              | macos-14       |
| 73 | ios          | sim-x86_64     | clang       | nextssl__ios__sim-x86_64               | *.dylib | macho_check         | macos-14       |

### Execution mode definitions

| Mode              | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `native`          | Load / exec directly on the host (ctypes or subprocess)                     |
| `pe_check`        | Verify MZ header (0x4D 0x5A) only — ARM/ARMv7 PE cannot run on x86_64      |
| `macho_check`     | Verify Mach-O magic only — device binary needs code-sign; x86_64 on M1     |
| `qemu_arm64`      | `qemu-aarch64` user-mode (`QEMU_LD_PREFIX=/usr/aarch64-linux-gnu`)          |
| `qemu_arm`        | `qemu-arm`   user-mode (`QEMU_LD_PREFIX=/usr/arm-linux-gnueabihf`)          |
| `qemu_x86`        | `qemu-i386`  user-mode (`QEMU_LD_PREFIX=/usr/i686-linux-gnu`)               |
| `qemu_riscv64`    | `qemu-riscv64` user-mode                                                    |
| `qemu_s390x`      | `qemu-s390x`   user-mode                                                    |
| `qemu_ppc64le`    | `qemu-ppc64le` user-mode                                                    |
| `qemu_loongarch64`| `qemu-loongarch64` user-mode (best-effort; may not be on all ubuntu-24.04)  |
| `node_wasm`       | `node test/wasm_runner.mjs <nextssl.js>` — Emscripten JS glue               |
| `wasi_wasm`       | `wasmtime <nextssl.wasm>` — pure WASI binary                                |

---

## 3. Mass smoke test — detailed specification

### File: `test/mass/run_mass.py`

```
Input:   --range / --id / --lib-dir / --full / --verbose
Output:  one line per variant; summary table; $GITHUB_STEP_SUMMARY
Exit:    0 = no FAIL; 1 = ≥1 FAIL
```

### Processing pipeline

```
for each variant in selected_range:
  ┌─ 1. Locate artifact dir ──────────────────────────────────────┐
  │   try  <lib-dir>/<vid>/          (preferred: numeric subdir)  │
  │   else <lib-dir>/<artifact-name>/  (CI download fallback)     │
  │   else → SKIP                                                 │
  └────────────────────────────────────────────────────────────────┘
  ┌─ 2. Find binary ──────────────────────────────────────────────┐
  │   glob  lib_glob  (e.g. "*.dll", "*.so", "*.dylib")           │
  │   else → SKIP                                                 │
  └────────────────────────────────────────────────────────────────┘
  ┌─ 3. Header check  (header_check.py) ─────────────────────────┐
  │   read first 4 bytes                                          │
  │   PE:     0x4D 0x5A                                           │
  │   ELF:    0x7F 0x45 0x4C 0x46                                 │
  │   Mach-O: one of six known magic values                       │
  │   WASM:   0x00 0x61 0x73 0x6D                                 │
  │   JS:     non-empty (Emscripten glue has no fixed magic)      │
  │   fail → FAIL header                                          │
  └────────────────────────────────────────────────────────────────┘
  ┌─ 4. Exec mode gate ───────────────────────────────────────────┐
  │   pe_check / macho_check → HEADER-ONLY (stop here)           │
  │   --full → delegate to run_tests.py (all groups)              │
  │   native on matching host → smoke_kat.py                      │
  │   anything else → HEADER-OK (QEMU/WASM needed)               │
  └────────────────────────────────────────────────────────────────┘
  ┌─ 5. Smoke KAT  (smoke_kat.py) ───────────────────────────────┐
  │   ctypes.CDLL(lib)                                            │
  │   nextssl_hash_compute("sha256", b"abc")                      │
  │   compare vs. hashlib.sha256(b"abc").digest()                 │
  │   pass → PASS; fail → FAIL KAT                               │
  └────────────────────────────────────────────────────────────────┘
```

### Header magic reference

| Format | Magic bytes (hex)                            | Used by                       |
|--------|----------------------------------------------|-------------------------------|
| PE     | `4D 5A`                                      | Windows .dll                  |
| ELF    | `7F 45 4C 46`                                | Linux .so, Android .so        |
| Mach-O | `CA FE BA BE` (fat)                          | macOS .dylib, iOS .dylib      |
|        | `CE FA ED FE` (32-bit LE)                    |                               |
|        | `CF FA ED FE` (64-bit LE)                    |                               |
|        | `FE ED FA CE` / `FE ED FA CF` (32/64-bit BE) |                               |
| WASM   | `00 61 73 6D`                                | .wasm (WASI)                  |
| JS     | (text; non-empty check)                      | Emscripten .js glue           |

---

## 4. Full KAT — detailed specification

### File: `test/full/run_full.py`

Delegates to `test/run_tests.py` for each variant.  Output of
`run_tests.py` is streamed when `--verbose` is set; captured otherwise.

### Algorithm coverage

#### Hash group (`--group hash`)

| Algorithm    | KAT source                   | Notes                          |
|--------------|------------------------------|--------------------------------|
| SHA-256      | KAT/data/hash/sha256.py      |                                |
| SHA-512      | KAT/data/hash/sha512.py      |                                |
| SHA-384      | KAT/data/hash/sha384.py      |                                |
| SHA3-256     | KAT/data/hash/sha3_256.py    |                                |
| SHA3-512     | KAT/data/hash/sha3_512.py    |                                |
| BLAKE2b-256  | KAT/data/hash/blake2b_256.py |                                |
| BLAKE2b-512  | KAT/data/hash/blake2b_512.py |                                |
| BLAKE2s-256  | KAT/data/hash/blake2s_256.py |                                |
| BLAKE3       | KAT/data/hash/blake3.py      |                                |
| MD5          | KAT/data/hash/md5.py         | legacy                         |
| SHA-1        | KAT/data/hash/sha1.py        | legacy                         |
| Skein-256    | KAT/data/hash/skein256.py    |                                |
| Skein-512    | KAT/data/hash/skein512.py    |                                |
| Argon2       | SKIP (memory-hard)           | too slow on CI                 |
| bcrypt       | SKIP (memory-hard)           |                                |
| scrypt       | SKIP (memory-hard)           |                                |

#### Modern group (`--group modern`)

| Sub-type               | API function                          |
|------------------------|---------------------------------------|
| HMAC-SHA256/512        | `nextssl_mac_hmac`                    |
| AES-128/256-CBC        | `nextssl_sym_aes_cbc_encrypt/decrypt` |
| AES-128/256-GCM        | `nextssl_aead_aes_gcm_encrypt/decrypt`|
| ChaCha20-Poly1305      | `nextssl_aead_chacha20_poly1305_*`    |
| Poly1305               | `nextssl_mac_poly1305`                |
| HKDF                   | `nextssl_kdf_hkdf`                    |
| PBKDF2                 | `nextssl_kdf_pbkdf2`                  |
| SM2 (if built)         | `nextssl_asym_sm2_*`                  |
| SipHash                | `nextssl_mac_siphash`                 |

#### Encoding group (`--group encoding`)

Python-stdlib reference vectors only — no C API call.
Covers: Base64, Hex, Bech32, Base58Check.

#### PQC group (`--group pqc`)

Structural KAT validation: type annotations, key-size checks.
Execution is skipped until a typed C API is available.

#### PoW group (`--group pow`)

Skipped by default.  With `--pow`: tests the fastest-path (nonce_max=1).

---

## 5. Range filter specification

The `-R` / `--range` flag accepts a comma-separated list of range specs.

### Grammar

```
spec     ::= part ("," part)*
part     ::= range | single
range    ::= integer "-" integer
single   ::= integer
integer  ::= [0-9]+
```

### Semantics

A range `lo-hi` includes every **registered** variant ID `v` where `lo ≤ v ≤ hi`.
Unregistered integers in the range are silently ignored.

### Named ranges (by platform)

| Description         | Range spec | IDs selected                         |
|---------------------|------------|--------------------------------------|
| Windows only        | `11-16`    | 11 12 13 14 15 16                    |
| Linux glibc only    | `21-28`    | 21 22 23 24 25 26 27 28              |
| Linux musl only     | `31-33`    | 31 32 33                             |
| macOS only          | `41-43`    | 41 42 43                             |
| WASM only           | `51-52`    | 51 52                                |
| Android only        | `61-64`    | 61 62 63 64                          |
| iOS only            | `71-73`    | 71 72 73                             |
| All Windows+Linux   | `11-33`    | 11–16 + 21–28 + 31–33 (17 variants) |
| All mobile          | `61-73`    | 61–64 + 71–73 (7 variants)           |
| Everything          | `11-73`    | all 29                               |

---

## 6. Artifact layout

```
artifacts/                    ← default --lib-dir
  11/                         ← variant 11 (win x86_64-msvc)
      nextssl.dll
  12/                         ← variant 12 (win x86-msvc)
      nextssl.dll
  21/                         ← variant 21 (linux-glibc x86_64-gcc)
      libnextssl.so
  22/
      libnextssl.so
  ...
  51/                         ← variant 51 (wasm emscripten)
      nextssl.js
      nextssl.wasm            ← side-car required by JS glue
  52/                         ← variant 52 (wasm wasi)
      nextssl.wasm
  ...
```

Alternatively, name subdirectories by artifact name
(e.g. `artifacts/nextssl__win__x86_64-msvc/`); the runner checks both.

---

## 7. CI integration patterns

### Pattern A: per-variant job (current `test.yml`)

Each variant gets its own job; jobs run in parallel.  Maximum parallelism.
One `dawidd6/action-download-artifact` step per job downloads the
artifact, then the job calls `run_tests.py --lib` directly.

### Pattern B: unified mass-test job

Download all 29 artifacts in one job, then run the mass runner:

```yaml
- uses: dawidd6/action-download-artifact@v6
  with:
    name: nextssl__*          # wildcard download (requires v6)
    path: artifacts/

- name: Unpack to numeric IDs
  run: python build/ci_unpack_artifacts.py artifacts/

- name: Mass smoke test
  run: python test/mass/run_mass.py --lib-dir artifacts/
```

### Pattern C: push gate (fast) + nightly full

```yaml
# On every push: mass gate
- run: python test/mass/run_mass.py -R 21 --lib-dir _art

# Nightly: full KAT across all variants
- run: python test/full/run_full.py --lib-dir artifacts/
```

---

## 8. Pass / fail criteria

| Category       | Pass condition                                              |
|----------------|-------------------------------------------------------------|
| Header check   | Magic bytes match expected format for the variant's exec_mode |
| Smoke KAT      | `nextssl_hash_compute("sha256", b"abc")` == `hashlib.sha256(b"abc").digest()` |
| Full KAT       | All vectors in all enabled KAT groups return expected output |
| Header-only    | Not a failure — counts as verified (cross-arch limitation)  |
| Skip           | Not a failure — counts as missing artifact                  |

**A run fails (exit code 1) if and only if at least one variant produces FAIL.**

---

## 9. Adding a new variant

1. Add one `Variant(...)` line to `_TABLE` in `test/variants.py`.
2. Choose the next available ID in the correct platform range.
3. Set `exec_mode` from the `EXEC_MODES` set.
4. Add the corresponding build step in `build.yml` / `build-variant.yml`.
5. Add the corresponding test job in `test.yml`.
6. No other files need to change.

---

## 10. Adding a new algorithm

1. Add KAT vectors to `KAT/data/<group>/<algo>.py`.
2. Add the dispatch handler in `test/run_tests.py` (the `run_<group>_group()`
   function or the per-handler dict).
3. The mass runner's smoke KAT does not need updating (it tests SHA-256 only).

---

## 11. Estimated runtimes

| Test type       | Variants   | Estimated wall time |
|-----------------|------------|---------------------|
| Mass (native)   | 29 serial  | ~5 s                |
| Mass (--full)   | 29 serial  | ~3–8 min            |
| Full KAT        | 1 variant  | ~10–30 s            |
| Full KAT        | 29 serial  | ~5–15 min           |
| CI parallel     | 29 jobs    | ~5 min (runner time)|

Times vary with hash algorithm count, KDF iteration count, and QEMU overhead.
Memory-hard algorithms are always skipped in KAT to keep CI times bounded.
