# Rules of Consistency

Conventions that apply across every file in this repository.

---

## Naming Conventions

### Source Files

| Pattern | Applies to |
|---|---|
| `nextssl_<action>.c/.h` | Layer 4 (primary) public API |
| `<category>_<action>.c/.h` | Layer 3 (main) and Layer 2 (base) |
| `<primitive>_<variant>.c/.h` | Layer 1 (partial) implementations |
| `<name>_types.h` | Struct/enum definitions only — no functions |
| `<name>_api.h` | Public entry points for a subsystem |

### Function Prefixes

| Prefix | Meaning |
|---|---|
| `nextssl_` | Public unified API (Layers 3–4) |
| `nextssl_root_` | Explicit-algorithm bypass (root interface) |
| `nextssl_dhcm_` | DHCM subsystem public API |
| `nextssl_config_` | Configuration subsystem |
| `ahs_` | Internal AHS (Argon2/Hash/Salt) utilities |
| `pow_` | PoW subsystem internal functions |
| `radix_` | Radix encoding utilities |

### Enum Values

All enum constants use `SCREAMING_SNAKE_CASE` with a module prefix:

```
DHCM_SHA256, DHCM_ARGON2ID
NEXTSSL_HASH_SHA256, NEXTSSL_AEAD_AES_256_GCM
RADIX_SUCCESS, RADIX_INVALID_INPUT
```

---

## Layer Import Rule

**No upward includes.**

Each layer may only include headers from the same layer or below:

```
Layer 4 (primary)  ← may include Layer 3, 2, 1
Layer 3 (main)     ← may include Layer 2, 1
Layer 2 (base)     ← may include Layer 1
Layer 1 (partial)  ← may include Layer 0 (implementation headers)
Layer 0            ← no includes from this project
```

Violating this rule introduces circular dependencies and breaks the
reproducible build system.  The CI build will reject upward includes.

---

## File Naming

- All source filenames: lowercase, underscores only — no hyphens, no spaces.
- All header guards: `SCREAMING_SNAKE_CASE` matching the file path, e.g.
  `NEXTSSL_ROOT_H`, `DHCM_TYPES_H`.
- Test files: prefixed `test_` (Python) or suffixed `_test.c` (C).
- Generated files in `bin/`: named by target stem (no extension as key in
  `bins.json`).

---

## Macro Definitions

| Macro | Required in | Purpose |
|---|---|---|
| `NEXTSSL_API` | All public headers | DLL export/import guard |
| `NEXTSSL_VARIANT_FULL` / `NEXTSSL_VARIANT_LITE` | Config | Build variant flag |
| `SOURCE_DATE_EPOCH=0` | Build system | Reproducible binary timestamps |

`NEXTSSL_API` expands to `__declspec(dllexport)` on Windows DLL builds,
`__attribute__((visibility("default")))` on ELF, and empty otherwise.

---

## Documentation Rules

- Every public function must have a Doxygen `@brief` comment.
- Output buffer sizes must be stated in the comment (e.g., `32 bytes`,
  `plen + 16`).
- Deprecated items are marked `@deprecated` and listed in `docs/api/CHANGELOG.md`.
