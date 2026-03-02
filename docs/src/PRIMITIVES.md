# Primitives

All low-level implementations live under `src/primitives/` or
`src/PQCrypto/`.  Legacy algorithms are in `src/legacy/`.

---

## src/primitives/hash/

| Algorithm | Output | Full | Lite |
|---|---|---|---|
| SHA-256 | 32 B | ✓ | ✓ |
| SHA-512 | 64 B | ✓ | ✓ |
| SHA-384 | 48 B | ✓ | — |
| SHA3-256 | 32 B | ✓ | — |
| SHA3-512 | 64 B | ✓ | — |
| BLAKE3 | variable | ✓ | ✓ |
| BLAKE2b | variable | ✓ | — |
| BLAKE2s | variable | ✓ | — |
| MD5 | 16 B | ✓ (legacy-alive) | — |
| SHA-1 | 20 B | ✓ (legacy-alive) | — |

---

## src/primitives/aead/

| Algorithm | Key | Nonce | Tag | Full | Lite |
|---|---|---|---|---|---|
| AES-256-GCM | 32 B | 12 B | 16 B | ✓ | ✓ |
| ChaCha20-Poly1305 | 32 B | 12 B | 16 B | ✓ | ✓ |
| AES-128-GCM | 16 B | 12 B | 16 B | ✓ | — |
| AES-256-CCM | 32 B | 13 B | 16 B | ✓ | — |
| AEGIS-256 | 32 B | 32 B | 32 B | ✓ | — |
| XChaCha20-Poly1305 | 32 B | 24 B | 16 B | ✓ | — |

---

## src/primitives/ecc/

| Algorithm | Public key | Secret key | Output | Full | Lite |
|---|---|---|---|---|---|
| X25519 | 32 B | 32 B | 32 B shared secret | ✓ | ✓ |
| Ed25519 | 32 B | 64 B | 64 B signature | ✓ | ✓ |
| ECDH P-256 | 65 B | 32 B | 32 B shared secret | ✓ | — |
| ECDH P-384 | 97 B | 48 B | 48 B shared secret | ✓ | — |
| ECDSA P-256 | 65 B | 32 B | 64 B signature | ✓ | — |

---

## src/primitives/cipher/

| Algorithm | Key sizes | Full | Lite |
|---|---|---|---|
| AES | 128 / 192 / 256 bit | ✓ | ✓ |
| ChaCha20 | 256 bit | ✓ | ✓ |

---

## src/primitives/mac/

| Algorithm | Output | Full | Lite |
|---|---|---|---|
| HMAC-SHA256 | 32 B | ✓ | ✓ |
| HMAC-SHA512 | 64 B | ✓ | — |
| Poly1305 | 16 B | ✓ | ✓ |

---

## src/PQCrypto/ — Post-Quantum

### KEM (crypto_kem/)

| Algorithm | Public key | Secret key | Ciphertext | Shared secret | Full | Lite |
|---|---|---|---|---|---|---|
| ML-KEM-512 | 800 B | 1632 B | 768 B | 32 B | ✓ | — |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B | 32 B | ✓ | — |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B | 32 B | ✓ | ✓ |

### Signatures (crypto_sign/)

| Algorithm | Public key | Secret key | Signature (max) | Full | Lite |
|---|---|---|---|---|---|
| ML-DSA-44 | 1312 B | 2560 B | 2420 B | ✓ | — |
| ML-DSA-65 | 1952 B | 4032 B | 3309 B | ✓ | — |
| ML-DSA-87 | 2592 B | 4896 B | 4627 B | ✓ | ✓ |

---

## src/legacy/

### alive/

Algorithms considered legacy but not cryptographically broken for all
use cases.  Available in COMPATIBILITY and RESEARCH profiles; blocked by
default.

| Algorithm | Category | Profile availability |
|---|---|---|
| SHA-1 | Hash | COMPATIBILITY, RESEARCH |
| MD5 | Hash | COMPATIBILITY, RESEARCH |
| RIPEMD-160 | Hash | COMPATIBILITY, RESEARCH |
| ECDSA P-256 | Sign | All profiles |

### unsafe/

Cryptographically broken algorithms.  Available ONLY in the RESEARCH profile.
Never use these in production.

| Algorithm | Category | Known break |
|---|---|---|
| MD2 | Hash | Preimage attacks |
| MD4 | Hash | Collision attacks |
| SHA-0 | Hash | Collision attacks |
| DES | Cipher | 56-bit key exhaustion |
| 3DES | Cipher | SWEET32, 112-bit effective |
