# GOAL — Project Architecture & Long-term Vision

> **One-line mission:** A fully self-contained, plugin-based C cryptographic
> library that covers all 776 catalogued algorithms, compiles to any target
> platform, and allows any algorithm to be included or excluded at build time
> with zero structural side-effects on the rest of the codebase.

---

## 1. What we are building

**NextSSL / Anon-leyline** is a multi-platform cryptographic library with:

- **776 algorithms** spanning 22 categories (see `algo.json`)
- **Pure C** (C99 minimum) core — no C++, no Rust, no Python at runtime
- **Cross-compiled** to all platforms in `/bin/` via CMake + the build scripts
  in `/build/platform/`
- **Plugin/plugout** algorithm model — every algorithm is an isolated
  compilation unit; toggling one changes binary size but nothing else
- **Flat, hash-addressed** source layout (see `job/0004_FLAT_HASH_LAYOUT.md`)
- **Dynamic documentation** generated from `algo.json` (see `ALGORITHM.html`,
  `SOURCE_REGISTRY.html`, `AFTER_BURN.html`)

---

## 2. Plugin/plugout system — core design rule

Every algorithm **must** satisfy all five constraints simultaneously:

### 2.1 Isolation
An algorithm's source files live in a single directory
(`src/<category>/<algo>/`). They must not `#include` anything from a sibling
algorithm directory. Only shared primitives under `src/common/` are allowed.

### 2.2 Capability declaration
Each algorithm directory contains exactly one `<algo>_api.h` that declares:
```c
/* capability flags, zero-terminated */
extern const NL_AlgoInfo nl_<algo>_info;

/* canonical function pointers */
extern const NL_AlgoOps  nl_<algo>_ops;
```
`NL_AlgoInfo` carries the category, status (active/legacy/upcoming), key
sizes, output sizes, and feature flags. `NL_AlgoOps` is the vtable.

### 2.3 Auto-registration
Each algorithm defines a single TU-local constructor:
```c
NL_ALGO_REGISTER(nl_<algo>_info, nl_<algo>_ops)
```
The `NL_ALGO_REGISTER` macro expands to a linker section entry on all
platforms. The core runtime discovers all registered algorithms at startup by
walking that section — no hand-written tables, no `#ifdef` forests.

### 2.4 Compile-time exclusion
To exclude an algorithm, remove its directory from `ALGO_SOURCES` in the
top-level `CMakeLists.txt` (or set `-DNL_DISABLE_<ALGO>=ON`). Nothing else
changes. The registration entry is simply not linked, the runtime sees nothing.

### 2.5 Family-level auto-removal
Algorithm directories are grouped by family prefix in CMake. If all members
of a family are excluded, the family's `src/<category>/<family>/` directory
produces zero object files and is automatically skipped by the build system.
No CMakeLists.txt changes are needed inside the family directory.

**Example:**
- Remove `argon2d` and `argon2id` → `argon2i` still compiles, `_argon` family
  directory still exists, binary shrinks by exactly those two objects.
- Remove all three → CMake skips the `src/password-kdf/argon/` subtree
  entirely. Family directory may be retained in the source tree but produces
  nothing in the build output.

---

## 3. Directory layout contract

```
src/
  <category>/          ← one directory per algo.json category key
    <family>/          ← optional family grouping (e.g., argon/, sha2/)
      <algo>/
        <algo>.c       ← implementation
        <algo>_api.h   ← canonical API (see §2.2)
        <algo>.h       ← internal types (optional)
        CMakeLists.txt ← add_library(nl_<algo> OBJECT <algo>.c)
                         target_include_directories(...)
                         nl_algo_register(nl_<algo>)   ← cmake helper

src/common/
  nl_algo_registry.h   ← NL_AlgoInfo, NL_AlgoOps, NL_ALGO_REGISTER
  nl_platform.h        ← endian, rotate, byte-order helpers
  nl_mem.h             ← secure_zero, constant-time compare
  mem/
  sanitizer/

examples/
  <category>/          ← gathered reference sources (see SOURCE_REFIX.md)
    <algo>/
      *.c / *.h        ← upstream reference
      kat.txt          ← known-answer test vectors
      <algo>_api.h     ← generated canonical wrapper
      CMakeLists.txt   ← ref_<algo> static object library

bin/
  <platform>/<arch>/   ← compiled output (libnextssl.a + libnextssl.so)
```

---

## 4. algo.json as the single source of truth

`algo.json` is the registry. It drives:

| Consumer | How it uses algo.json |
|----------|-----------------------|
| `build/check_algos.py` | validates every src dir matches an entry |
| `build/check_exports.py` | validates every registered symbol matches an entry |
| `ALGORITHM.html` | documentation generated from active/legacy/upcoming lists |
| `SOURCE_REGISTRY.html` | source coverage visualization |
| `AFTER_BURN.html` | post-merge analysis of coverage gaps |
| `SOURCE_REFIX.md` | task tracking (this file system) |
| CMake `ALGO_SOURCES` | generated list of directories to compile |

**Source flags (future enhancement):** Each entry in `algo.json` will gain:
```json
"src": true,          // reference source gathered in /examples
"impl": true,         // production implementation in /src
"tests": true,        // KAT tests present
"acvp": true          // ACVP validation vectors present
```

---

## 5. Build system rules

- CMake minimum 3.16
- Each `src/<category>/<algo>/CMakeLists.txt` calls `nl_algo_register()` which
  appends the object library to a global `NL_ALGO_OBJECTS` property.
- The top-level `CMakeLists.txt` collects `NL_ALGO_OBJECTS` and links into
  `libnextssl`.
- Platform files in `build/platform/` set compiler flags, ABI targets, and
  feature detection (AES-NI, NEON, AVX2, etc.) — algorithms detect these via
  CMake feature variables, not `#ifdef __ARM_NEON` scatter.
- `build/build.py` is the high-level driver that orchestrates cross-compilation
  across all targets.

---

## 6. Sustainability principles

1. **No monolithic headers.** Each algorithm owns its header. One algorithm's
   change cannot break another's compilation.

2. **No global mutable state** (except the registration section, which is
   read-only after startup). Algorithms are stateless objects; callers own
   all context memory.

3. **Constant-time by default.** Any algorithm that handles secret material
   must be constant-time. The sanitizer harness in `src/common/sanitizer/`
   provides VALGRIND_MAKE_MEM_UNDEFINED hooks for CI validation.

4. **Zero dynamic allocation in the algorithm core.** All heap allocation is
   the caller's responsibility. Algorithms declare their context size via
   `NL_AlgoInfo.ctx_size` and accept a caller-provided buffer.

5. **Test vector first.** No implementation merges without a passing KAT.
   ACVP vectors from `examples/ACVP-Server/` are the canonical source.

6. **One algorithm, one status.** An algorithm is exactly one of: `active`,
   `legacy`, or `upcoming`. `legacy` means it compiles but is flagged
   deprecated in its `NL_AlgoInfo`. `upcoming` means the source directory
   exists as a stub but `NL_ALGO_REGISTER` is gated on
   `-DNL_ENABLE_UPCOMING=ON`.

---

## 7. Work sequence

The following phases must be completed in order:

| Phase | Description | Key documents |
|-------|-------------|---------------|
| **P0** | Source gathering | `SOURCE_REFIX.md` — complete all 22 sections |
| **P1** | API wrapping | Generate `<algo>_api.h` for each sourced algo |
| **P2** | KAT wiring | Populate `kat.txt` and wire into test runner |
| **P3** | Production impl | Port or write `src/<category>/<algo>/` for actives |
| **P4** | CI / ACVP | Wire ACVP-Server, run CI across all platforms |
| **P5** | Optimization | Add AVX2/NEON/AES-NI paths behind CMake features |
| **P6** | Documentation | Regenerate HTML docs from completed algo.json |

**Current position: start of P0.**

---

## 8. Constraints and non-goals

- **Not a TLS stack.** Protocol primitives are algorithm-level only; no
  full TLS/DTLS/SSH handshake state machine is in scope.
- **Not a PKI CA.** Certificate operations are codec + validation only.
- **No JavaScript / WASM bindings yet.** The WASM target in `/bin/wasm/`
  produces a raw `.wasm`; JS glue is out of scope for now.
- **No Go / Python / Rust wrappers** in the initial phases. The C ABI is
  the integration surface.
- **Do not break the flat-hash layout.** See `job/0004_FLAT_HASH_LAYOUT.md`
  before touching any `build/flatten_hash.py` logic.
