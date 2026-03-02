# Layers

NextSSL uses a strict four-layer header hierarchy.  Each layer has a single
responsibility, and the import direction is one-way: downward only.

---

## Layer 1 — Partial

**Folder:** `src/interfaces/partial/`

**Rule:** One header per primitive variant.  No cross-module includes.  No
validation logic.

A partial header wraps exactly one algorithm implementation and exposes the
raw operation.  Examples:

- `partial/hash/sha256.h` — raw SHA-256 compress + digest
- `partial/aead/aes256gcm.h` — raw AES-256-GCM encrypt/decrypt
- `partial/ecc/x25519.h` — raw X25519 scalar multiply

Partial headers are not part of the public API.  They are only included by
Layer 2 (base).

---

## Layer 2 — Base

**Folder:** `src/interfaces/base/`

**Rule:** Aggregates one or more partial headers for a single algorithm
family.  Adds parameter validation and safe defaults.  No cross-category
includes.

A base header provides the validated, algorithm-specific function for a
given category.  It may include multiple partial headers for the same
algorithm (e.g., key expansion + encryption for AES), but must not include
headers from a different category.

Examples:

- `base/hash/sha256.h` — validates input, calls partial SHA-256
- `base/aead/aes256gcm.h` — validates key/nonce sizes, calls partial AES-GCM
- `base/radix/base64.h` — validates buffers, calls partial base64 codec

---

## Layer 3 — Main

**Folder:** `src/interfaces/main/`

**Rule:** Category-level API.  Aggregates base headers for that category.
Adds profile-aware dispatch.  Must not include headers from a different
category's main layer.

A main header presents the full API for one functional category — all
supported algorithms in that category, with consistent naming.

Examples:

- `main/hash.h` — all hash algorithms, dispatch table
- `main/aead.h` — all AEAD algorithms, auto-nonce helpers
- `main/pqc.h` — ML-KEM, ML-DSA entry points

---

## Layer 4 — Primary

**Folder:** `src/interfaces/primary/`

**Rule:** One header per build variant.  Includes all Layer 3 main headers.
Presents the single unified API that consumers `#include`.

This layer contains exactly two headers:

- `primary/full/nextssl.h` — full variant (all algorithms)
- `primary/lite/nextssl_lite.h` — lite variant (9 core algorithms, ~500 KB)

Both variants also include `root/nextssl_root.h` at the bottom of the header
to provide the explicit-algorithm bypass interface.

---

## Import Rule Summary

```
Layer 4 → may include Layer 3, 2, 1
Layer 3 → may include Layer 2, 1
Layer 2 → may include Layer 1
Layer 1 → may include Layer 0 implementation headers only
```

**No upward includes.** A lower layer must never include a higher layer's
header.  This rule is enforced at build time by the CI pipeline.
