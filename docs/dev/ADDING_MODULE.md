# Adding a New Algorithm Module

This guide walks through adding a new hash algorithm (`SHA3-256`) as a
concrete example.  The same pattern applies to AEAD, KDF, sign, and KEM
modules.

---

## Step 1 — Add the Implementation

Place the C source in the appropriate `src/primitives/` subdirectory:

```
src/primitives/hash/sha3_256.c
src/primitives/hash/sha3_256.h
```

Rules:

- No includes from any interface layer (`partial/`, `base/`, `main/`, `primary/`).
- If the header belongs in `public/`, mark functions with `NEXTSSL_API`.
- Keep the filename lowercase with underscores.

**What breaks if skipped:** Layer 1 headers will reference a file that does
not exist; the build will fail with a missing source error.

---

## Step 2 — Add a Partial Header

Create `src/interfaces/partial/hash/sha3_256.h`:

```c
#ifndef PARTIAL_HASH_SHA3_256_H
#define PARTIAL_HASH_SHA3_256_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../primitives/hash/sha3_256.h"

// Thin wrapper — no validation, no dispatch
int partial_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);

#endif
```

**What breaks if skipped:** The base layer has nothing to aggregate; you will
either skip base entirely (breaking the layer rule) or include the primitive
directly from base (violating the no-upward-include rule).

---

## Step 3 — Update the Base Header

Edit `src/interfaces/base/hash/sha3_256.h` (create if new):

```c
#include "../../partial/hash/sha3_256.h"

// Add parameter validation, safe defaults
int base_sha3_256(const uint8_t *data, size_t len, uint8_t out[32]);
```

Add the algorithm to the base dispatch table in `base/hash.h`:

```c
case NEXTSSL_HASH_SHA3_256:
    return base_sha3_256(data, len, out);
```

**What breaks if skipped:** The main layer cannot dispatch to this algorithm;
callers requesting SHA3-256 will get `NEXTSSL_ERR_ALGO_UNAVAIL`.

---

## Step 4 — Register in Config

Add the enum value in `src/config/config.h`:

```c
NEXTSSL_HASH_SHA3_256 = 7,  // (or next available value)
```

Update `nextssl_config_algo_available()` to return 1 for the new ID.
Update the profile tables to include or exclude the algorithm as appropriate.

**What breaks if skipped:** `nextssl_init_custom()` will reject the algorithm
ID as invalid; `nextssl_config_algo_available()` will return 0 even after
the binary is compiled with the implementation.

---

## Step 5 — Add a Build Script and Test

Create `script/gen/partial/hash/sha3_256.py` following the pattern of an
existing partial gen script.  Then create `script/test/partial/hash/sha3_256.py`.

Register both in the relevant `LOAD_MAP` and `LOAD_MAP_ALL` dictionaries in
`runner.py`.

**What breaks if skipped:** `python runner.py --build hash:partial` will not
compile the new module; `python runner.py --test hash:partial` will not run
any tests for it.

---

## Checklist

- [ ] `src/primitives/hash/sha3_256.c` + `.h` created
- [ ] `src/interfaces/partial/hash/sha3_256.h` created
- [ ] `src/interfaces/base/hash/sha3_256.h` created and registered in dispatch
- [ ] Enum value added to `config.h`
- [ ] `nextssl_config_algo_available()` updated
- [ ] Profile tables updated
- [ ] Gen script created and registered in `LOAD_MAP`
- [ ] Test script created and registered in `LOAD_MAP`
- [ ] `docs/src/PRIMITIVES.md` table updated
- [ ] `docs/api/PROFILES.md` enum table updated
- [ ] `docs/api/CHANGELOG.md` vNEXT entry added
