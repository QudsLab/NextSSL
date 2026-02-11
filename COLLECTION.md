# NextSSL Collection Status

This document tracks the current inventory of cryptographic implementations in `src` against the roadmap in `NEXT.md`.

## ✅ Implemented / Available

### Post-Quantum Cryptography (PQCrypto)
**Key Encapsulation Mechanisms (KEM)**
*   **ML-KEM (Kyber):** `ml-kem-1024` (and likely 512/768 variants)
*   **HQC:** `hqc-128`, `hqc-192`, `hqc-256`
*   **McEliece:**
    *   `mceliece348864`, `mceliece348864f`
    *   `mceliece460896`, `mceliece460896f`
    *   `mceliece6688128`, `mceliece6688128f`
    *   `mceliece6960119`, `mceliece6960119f`
    *   `mceliece8192128`, `mceliece8192128f`

**Digital Signatures**
*   **Falcon:** `falcon-512`, `falcon-1024` (plus padded variants)
*   **ML-DSA (Dilithium):** `ml-dsa-44`, `ml-dsa-65` (likely 87 as well)
*   **SPHINCS+:** `sphincs-sha2` and `sphincs-shake` (128/192/256, simple/robust, fast/small variants)

**Common Utilities**
*   **SHAKE / cSHAKE:** `fips202` (SHAKE128/256), `sp800-185` (cSHAKE128/256)
*   **AES:** Internal implementations for RNG
*   **SHA2:** Internal implementations
*   **HKDF:** HKDF-SHA256, HKDF-SHA3-256/512, HKDF-Expand-Label
*   **KDF:** XOF-based KDF (SHAKE256)

### Classical Hashing (BaseHash)
*   **SHA-2:** `sha224`, `sha256`, `sha512`
*   **SHA-3:** `sha3`, `sha3_224`, `sha3_384`
*   **BLAKE:** `blake2b`, `blake2s`, `blake3`
*   **Legacy/Other:** `md2`, `md4`, `md5`, `sha0`, `sha1`, `ripemd` (128/160/256/320), `whirlpool`, `has160`, `keccak`, `nt`, `shake`

### Symmetric Encryption (BaseEncryption)
*   **AES Modes:**
    *   Authenticated: `AES_GCM`, `AES_CCM`, `AES_EAX`, `AES_GCM_SIV`, `AES_OCB`
    *   Standard: `AES_CBC`, `AES_CFB`, `AES_CTR`, `AES_ECB`, `AES_OFB`
    *   Specialized: `AES_CMAC`, `AES_FPE`, `AES_KW`, `AES_Poly1305`, `AES_SIV`, `AES_XTS`
*   **Monocypher (Comprehensive Suite):**
    *   **Authenticated Encryption:** ChaCha20-Poly1305 (`crypto_aead_lock`)
    *   **Stream Cipher:** XChaCha20, ChaCha20 (`crypto_chacha20_*`)
    *   **MAC:** Poly1305 (`crypto_poly1305`)
    *   **Key Exchange:** X25519 (`crypto_x25519`)
    *   **Signatures:** EdDSA (Ed25519) (`crypto_eddsa_*`)
    *   **Hashing:** BLAKE2b (`crypto_blake2b`)
    *   **Elligator 2:** (`crypto_elligator_*`)

### Public Key / Asymmetric (Asymmetric)
*   **Ed25519:** Standalone implementation in `src/Asymmetric/Ed25519`
*   **Ristretto255:** Ported from libsodium in `src/Asymmetric/Ristretto255`
*   **Elligator 2:** Ported from Monocypher in `src/Asymmetric/Elligator2`

### Password Hashing (AdvanceHash)
*   **Argon2:** `Argon2d`, `Argon2i`, `Argon2id` (Core and Threading support)

---

## ❌ Missing / To Be Implemented

### Classical Crypto / Groups
*   [ ] **X448** (Source: `wolfssl` / `curve448`)
*   [ ] **Ed448** (Source: `wolfssl` / `ed448`)

### Post-Quantum
*   *(No additional planned items - Hybrid schemes to be orchestrated via manual seeding of primitives)*

### Hash / XOF
*   [ ] **TupleHash**
*   [ ] **ParallelHash**

### MAC / Authentication
*   **HMAC:** `hmac` (Generic HMAC-SHA256 implemented in `src/BaseHash/hmac`)
*   **SipHash:** `siphash` (SipHash-2-4 implemented in `src/BaseHash/siphash`)
*   **KMAC:** `kmac128`, `kmac256` (Implemented in `src/BaseHash/kmac` via SHA3)

### KDF / Key Derivation
*   [ ] **HKDF-BLAKE2**
