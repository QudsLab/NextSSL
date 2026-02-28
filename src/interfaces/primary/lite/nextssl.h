/**
 * @file nextssl_lite.h
 * @brief NextSSL Lite - Unified Lite API (9 core algorithms)
 * 
 * Ultra-simple API for embedded/mobile use cases.
 * Binary size: ~500KB (vs ~5MB full variant)
 * 
 * Lite Algorithms (9 total):
 * - Hash: SHA-256, SHA-512, BLAKE3
 * - AEAD: AES-256-GCM, ChaCha20-Poly1305
 * - KDF: HKDF, Argon2id
 * - PQC: Kyber1024 (KEM), Dilithium5 (Sign)
 * 
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_LITE_H
#define NEXTSSL_LITE_H

#include "config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ============================================================
 * Simplified Hash API
 * ============================================================ */

/**
 * @brief Hash data (default: SHA-256)
 * 
 * Simple wrapper for SHA-256 hashing
 * 
 * @param data Input data
 * @param len Input length
 * @param output Output buffer (32 bytes)
 * @return 0 on success
 * 
 * Example:
 *   uint8_t hash[32];
 *   nextssl_hash((uint8_t*)"hello", 5, hash);
 */
NEXTSSL_API int nextssl_hash(const uint8_t *data, size_t len, uint8_t *output);

/**
 * @brief Hash data with specific algorithm
 * 
 * Supported: "SHA-256" (default), "SHA-512", "BLAKE3"
 * 
 * @param algorithm Algorithm name
 * @param data Input data
 * @param len Input length
 * @param output Output buffer (32 or 64 bytes depending on algorithm)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_hash_ex(
    const char *algorithm,
    const uint8_t *data,
    size_t len,
    uint8_t *output
);

/* ============================================================
 * Simplified Encryption API
 * ============================================================ */

/**
 * @brief Encrypt data (default: AES-256-GCM)
 * 
 * @param key 32-byte encryption key
 * @param nonce 12-byte nonce (must be unique per key)
 * @param plaintext Input data
 * @param plen Input length
 * @param ciphertext Output buffer (plen + 16 bytes for authentication tag)
 * @return 0 on success
 * 
 * Example:
 *   uint8_t key[32], nonce[12], ct[20]; // 4 bytes + 16 byte tag
 *   nextssl_encrypt(key, nonce, (uint8_t*)"test", 4, ct);
 */
NEXTSSL_API int nextssl_encrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plen,
    uint8_t *ciphertext
);

/**
 * @brief Decrypt data (default: AES-256-GCM)
 * 
 * @param key 32-byte decryption key
 * @param nonce 12-byte nonce
 * @param ciphertext Input data (includes 16-byte tag)
 * @param clen Input length
 * @param plaintext Output buffer (clen - 16 bytes)
 * @return 0 on success, negative on authentication failure
 */
NEXTSSL_API int nextssl_decrypt(
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t clen,
    uint8_t *plaintext
);

/**
 * @brief Encrypt with specific algorithm
 * 
 * Supported: "AES-256-GCM" (default), "ChaCha20-Poly1305"
 */
NEXTSSL_API int nextssl_encrypt_ex(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *plaintext,
    size_t plen,
    uint8_t *ciphertext
);

NEXTSSL_API int nextssl_decrypt_ex(
    const char *algorithm,
    const uint8_t *key,
    const uint8_t *nonce,
    const uint8_t *ciphertext,
    size_t clen,
    uint8_t *plaintext
);

/* ============================================================
 * Password Hashing API
 * ============================================================ */

/**
 * @brief Hash password (default: Argon2id)
 * 
 * Uses recommended parameters for password storage
 * 
 * @param password Password bytes
 * @param plen Password length
 * @param salt 16-byte salt
 * @param output 32-byte hash output
 * @return 0 on success
 * 
 * Example:
 *   uint8_t salt[16], hash[32];
 *   nextssl_random(salt, 16); // Generate random salt
 *   nextssl_password_hash((uint8_t*)"mypassword", 10, salt, hash);
 */
NEXTSSL_API int nextssl_password_hash(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    uint8_t *output
);

/**
 * @brief Verify password against hash
 * 
 * @param password Password to verify
 * @param plen Password length
 * @param salt 16-byte salt
 * @param expected_hash Expected hash value
 * @return 0 if password matches, negative otherwise
 */
NEXTSSL_API int nextssl_password_verify(
    const uint8_t *password,
    size_t plen,
    const uint8_t *salt,
    const uint8_t *expected_hash
);

/* ============================================================
 * Key Exchange API
 * ============================================================ */

/**
 * @brief Generate keypair
 * 
 * @param public_key Output public key (32 bytes classical, 1568 bytes PQC)
 * @param secret_key Output secret key (32 bytes classical, 3168 bytes PQC)
 * @param pqc 0=classical (X25519), 1=post-quantum (Kyber1024)
 * @return 0 on success
 * 
 * Example (classical):
 *   uint8_t pk[32], sk[32];
 *   nextssl_keygen(pk, sk, 0); // X25519 keypair
 * 
 * Example (post-quantum):
 *   uint8_t pk[1568], sk[3168];
 *   nextssl_keygen(pk, sk, 1); // Kyber1024 keypair
 */
NEXTSSL_API int nextssl_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
);

/**
 * @brief Perform key exchange
 * 
 * Classical (X25519): Computes shared secret directly
 * Post-quantum (Kyber1024): Performs encapsulation
 * 
 * @param my_secret My secret key
 * @param their_public Their public key
 * @param shared_secret Output shared secret (32 bytes)
 * @param ciphertext Output ciphertext (1568 bytes for PQC, unused for classical)
 * @param pqc 0=classical, 1=post-quantum
 * @return 0 on success
 */
NEXTSSL_API int nextssl_keyexchange(
    const uint8_t *my_secret,
    const uint8_t *their_public,
    uint8_t *shared_secret,
    uint8_t *ciphertext,
    int pqc
);

/**
 * @brief Decapsulate key exchange (PQC only)
 * 
 * @param ciphertext Received ciphertext (1568 bytes)
 * @param my_secret My secret key (3168 bytes)
 * @param shared_secret Output shared secret (32 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_keyexchange_decaps(
    const uint8_t *ciphertext,
    const uint8_t *my_secret,
    uint8_t *shared_secret
);

/* ============================================================
 * Digital Signature API
 * ============================================================ */

/**
 * @brief Generate signature keypair
 * 
 * @param public_key Output public key (32 bytes classical, 2592 bytes PQC)
 * @param secret_key Output secret key (64 bytes classical, 4864 bytes PQC)
 * @param pqc 0=classical (Ed25519), 1=post-quantum (Dilithium5)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_sign_keygen(
    uint8_t *public_key,
    uint8_t *secret_key,
    int pqc
);

/**
 * @brief Sign message
 * 
 * @param message Message to sign
 * @param mlen Message length
 * @param secret_key Secret key
 * @param signature Output signature (64 bytes Ed25519, 4627 bytes Dilithium5)
 * @param pqc 0=classical, 1=post-quantum
 * @return 0 on success
 */
NEXTSSL_API int nextssl_sign(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *secret_key,
    uint8_t *signature,
    int pqc
);

/**
 * @brief Verify signature
 * 
 * @param message Message that was signed
 * @param mlen Message length
 * @param signature Signature to verify
 * @param public_key Public key
 * @param pqc 0=classical, 1=post-quantum
 * @return 0 if valid, negative if invalid
 */
NEXTSSL_API int nextssl_verify(
    const uint8_t *message,
    size_t mlen,
    const uint8_t *signature,
    const uint8_t *public_key,
    int pqc
);

/* ============================================================
 * Utility Functions
 * ============================================================ */

/**
 * @brief Generate cryptographically secure random bytes
 * 
 * @param output Output buffer
 * @param len Number of bytes to generate
 * @return 0 on success
 */
NEXTSSL_API int nextssl_random(uint8_t *output, size_t len);

/**
 * @brief Get NextSSL Lite version
 * 
 * @return Version string (e.g., "0.1.0-beta-lite")
 */
NEXTSSL_API const char* nextssl_version(void);

/**
 * @brief Check if algorithm is available
 * 
 * @param algorithm Algorithm name (e.g., "SHA-256", "AES-256-GCM")
 * @return 1 if available, 0 if not
 */
NEXTSSL_API int nextssl_has_algorithm(const char *algorithm);

/**
 * @brief List all available algorithms
 * 
 * @param buffer Output buffer
 * @param size Buffer size
 * @return Number of algorithms (9 for lite)
 */
NEXTSSL_API int nextssl_list_algorithms(char *buffer, size_t size);

/**
 * @brief Initialize NextSSL (optional, called automatically)
 * 
 * @return 0 on success
 */
NEXTSSL_API int nextssl_init(void);

/**
 * @brief Cleanup NextSSL resources
 */
NEXTSSL_API void nextssl_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_H */
