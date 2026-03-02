# Modules

Each module in `src/` has a defined partial → base → main output path.
The table below lists the key outputs at each layer for every module.

---

## Module Table

| Module | Partial layer | Base layer | Main layer |
|---|---|---|---|
| Hash | `partial/hash/<algo>.h` | `base/hash/<algo>.h` | `main/hash.h` |
| AEAD | `partial/aead/<algo>.h` | `base/aead/<algo>.h` | `main/aead.h` |
| Cipher | `partial/cipher/<algo>.h` | `base/cipher/<algo>.h` | `main/cipher.h` |
| ECC | `partial/ecc/<algo>.h` | `base/ecc/<algo>.h` | `main/ecc.h` |
| MAC | `partial/mac/<algo>.h` | `base/mac/<algo>.h` | `main/mac.h` |
| PQCrypto | `partial/pqc/<algo>.h` | `base/pqc/<algo>.h` | `main/pqc.h` |
| KDF | `partial/kdf/<algo>.h` | `base/kdf/<algo>.h` | `main/kdf.h` |
| Radix | `partial/radix/<enc>.h` | `base/radix/<enc>.h` | `main/radix.h` |

---

## Module Details

### Hash

Implementations in `src/primitives/hash/`.  Includes SHA-2 (256/384/512),
SHA-3 (256/512), BLAKE2b/2s/3, and legacy digests (SHA-1, MD5).
Profile controls which algorithms are exposed at Layer 4.

### AEAD

Implementations in `src/primitives/aead/`.  Includes AES-256-GCM,
ChaCha20-Poly1305, AES-128-GCM, AES-256-CCM, AEGIS-256.
Full variant only for algorithms beyond the first two.

### Cipher

Raw stream/block primitives in `src/primitives/cipher/`.  Not directly
exposed at Layer 4; used internally by AEAD module.

### ECC

Classical asymmetric operations in `src/primitives/ecc/`.
X25519 (key exchange) and Ed25519 (signatures).

### MAC

Message authentication in `src/primitives/mac/`.
HMAC-SHA256/512, Poly1305.  Consumed by AEAD and KDF modules.

### PQCrypto

Post-quantum implementations in `src/PQCrypto/`.
`crypto_kem/` — ML-KEM (Kyber) variants (512/768/1024).
`crypto_sign/` — ML-DSA (Dilithium) variants (44/65/87).

### DHCM

Difficulty/Hash Cost Model in `src/DHCM/`.  Standalone subsystem —
not included in the standard Layer 3/4 dispatch.  Accessed via
`src/DHCM/utils/dhcm_api.h`.  See [docs/api/DHCM.md](../api/DHCM.md).

### PoW

> **Note:** The PoW module (`src/PoW/`) is unstable and subject to structural
> change.  The client/server/combined split and dependency on `src/utils/radix/`
> are expected to be revised before the stable 1.0 release.  Do not depend on
> internal PoW headers.

Proof-of-Work client, server, and combined entry points.  Uses SHA-256 via
`src/utils/radix/base64.c` for challenge encoding.

### Utils

Support code in `src/utils/`:

| Subdirectory | Contents |
|---|---|
| `encoding/` | Legacy encoding path (being superseded by radix) |
| `radix/` | Radix encoding — `base64.c` active; others stubbed for vNEXT |
| `hash/` | Hash utility wrappers |
| `kdf/` | HKDF, Argon2 wrappers |
| `drbg/` | Deterministic random bit generator |
| `pow/` | PoW helper code |
| `pqc/` | PQC utility wrappers |
