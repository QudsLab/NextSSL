# Source Map

The `src/` tree is organised into four compilation layers plus a set of
standalone subsystems.  Code flows from low-level primitives up to the single
unified header that consumers see.

---

## Layer Diagram

```
┌─────────────────────────────────────────────┐
│  Layer 4 — primary (nextssl.h / nextssl_lite.h)      │
│  Single header, profile-driven dispatch          │
└──────────────────┬──────────────────────────┘
                   │ includes
┌──────────────────▼──────────────────────────┐
│  Layer 3 — main                              │
│  Category-level APIs (hash, aead, kdf, …)   │
└──────────────────┬──────────────────────────┘
                   │ includes
┌──────────────────▼──────────────────────────┐
│  Layer 2 — base                              │
│  Algorithm-specific functions + validation  │
└──────────────────┬──────────────────────────┘
                   │ includes
┌──────────────────▼──────────────────────────┐
│  Layer 1 — partial                           │
│  Single-primitive building blocks           │
└──────────────────┬──────────────────────────┘
                   │ links to
┌──────────────────▼──────────────────────────┐
│  Layer 0 — implementations                  │
│  C source in src/primitives/, PQCrypto/, …  │
└─────────────────────────────────────────────┘
```

Each layer imports only from the same layer or below.
See [docs/src/LAYERS.md](LAYERS.md) for the detailed rules.

---

## Layer Summary

| Layer | Folder | Role |
|---|---|---|
| 4 — primary | `src/interfaces/primary/` | Public entry point — one per variant |
| 3 — main | `src/interfaces/main/` | Per-category high-level API |
| 2 — base | `src/interfaces/base/` | Algorithm-specific with input validation |
| 1 — partial | `src/interfaces/partial/` | Single-primitive, no cross-module deps |

---

## Module Summary

| Module | Source root | Description |
|---|---|---|
| Hash | `src/primitives/hash/` | SHA-2, SHA-3, BLAKE2/3, legacy digests |
| AEAD | `src/primitives/aead/` | AES-256-GCM, ChaCha20-Poly1305, experimental |
| ECC | `src/primitives/ecc/` | X25519, Ed25519 |
| MAC | `src/primitives/mac/` | HMAC, Poly1305 |
| Cipher | `src/primitives/cipher/` | AES, ChaCha20 raw |
| PQCrypto | `src/PQCrypto/` | ML-KEM (Kyber), ML-DSA (Dilithium) |
| DHCM | `src/DHCM/` | Difficulty/Hash Cost Model subsystem |
| PoW | `src/PoW/` | Proof-of-Work client/server/combined |
| Utils | `src/utils/` | Encoding, KDF helpers, DRBG, PoW support |

See [docs/src/MODULES.md](MODULES.md) for per-module details and
[docs/src/PRIMITIVES.md](PRIMITIVES.md) for the full primitive table.
