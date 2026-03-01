/**
 * @file nextssl.h
 * @brief Layer 4: Primary unified NextSSL interface
 * @layer primary
 * @category all
 * @visibility public
 * 
 * ========== NEXTSSL - Next-Generation Security Library ==========
 * 
 * Ultra-simple, security-first cryptographic API. One header for everything.
 * 
 * **Quick Start:**
 * ```c
 * #include <nextssl.h>
 * 
 * // Encrypt data
 * uint8_t key[32] = {...};
 * uint8_t ciphertext[1024];
 * size_t ciphertext_len;
 * nextssl_encrypt(key, plaintext, plaintext_len, ciphertext, &ciphertext_len);
 * 
 * // Hash password
 * char password_hash[128];
 * nextssl_password_hash("user_password", 13, password_hash, 128);
 * 
 * // Generate random bytes
 * uint8_t random_data[32];
 * nextssl_random(random_data, 32);
 * ```
 * 
 * **Architecture:**
 * - Layer 4 (Primary): This file - unified simple interface
 * - Layer 3 (Main): High-level category APIs
 * - Layer 2 (Base): Algorithm-specific functions with validation
 * - Layer 1 (Partial): Low-level primitives (hidden)
 * - Layer 0: Implementations (hidden)
 * 
 * **Security Defaults:**
 * - Encryption: AES-256-GCM (hardware-accelerated)
 * - Hashing: SHA-256 (FIPS 180-4)
 * - Password hashing: Argon2id (RFC 9106, OWASP 2023)
 * - Key exchange: X25519 (RFC 7748)
 * - Signatures: Ed25519 (RFC 8032)
 * - Post-quantum: ML-KEM-768, ML-DSA-65 (NIST FIPS 203/204)
 * 
 * @version 0.0.1-beta
 * @date 2026-02-28
 * @compliance FIPS 180-4, FIPS 202, FIPS 203, FIPS 204, RFC 9106, RFC 7748, RFC 8032
 * @license MIT (see LICENSE file)
 */

#ifndef NEXTSSL_H
#define NEXTSSL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/* ========== Version Information ========== */

#define NEXTSSL_VERSION_MAJOR 0
#define NEXTSSL_VERSION_MINOR 0
#define NEXTSSL_VERSION_PATCH 1
#define NEXTSSL_VERSION_STRING "0.0.1-beta"

/**
 * Get NextSSL version string
 * @return Version string (e.g., "0.0.1-beta")
 */
const char* nextssl_version(void);

/**
 * Get build variant
 * @return "lite" or "full"
 */
const char* nextssl_variant(void);

/**
 * Get security level of the active configuration profile
 * @return "modern-safe", "compliance-safe", "post-quantum", etc.
 */
const char* nextssl_security_level(void);

/* ========== Core Cryptography ========== */

/**
 * Generate cryptographically secure random bytes
 * 
 * @param output Output buffer
 * @param length Number of random bytes
 * @return 0 on success, negative on error
 */
int nextssl_random(uint8_t *output, size_t length);

/**
 * Encrypt data (AES-256-GCM with auto nonce)
 * 
 * @param key 32-byte key
 * @param plaintext Data to encrypt
 * @param plaintext_len Length of plaintext
 * @param ciphertext Output (allocate plaintext_len + 28)
 * @param ciphertext_len Actual output length
 * @return 0 on success, negative on error
 */
int nextssl_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * Decrypt data
 * 
 * @param key 32-byte key
 * @param ciphertext Encrypted data
 * @param ciphertext_len Length of ciphertext
 * @param plaintext Output buffer
 * @param plaintext_len Actual plaintext length
 * @return 0 on success, negative on error/auth failure
 */
int nextssl_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len);

/**
 * Hash data (SHA-256)
 * 
 * @param data Data to hash
 * @param data_len Length of data
 * @param hash Output (32 bytes)
 * @return 0 on success, negative on error
 */
int nextssl_hash(
    const uint8_t *data, size_t data_len,
    uint8_t hash[32]);

/**
 * Derive key from input (HKDF-SHA256)
 * 
 * @param input Input key material
 * @param input_len Length of input
 * @param context Optional context (NULL if unused)
 * @param output Derived key output
 * @param output_len Desired output length
 * @return 0 on success, negative on error
 */
int nextssl_derive_key(
    const uint8_t *input, size_t input_len,
    const char *context,
    uint8_t *output, size_t output_len);

/* ========== Password Hashing ========== */

/**
 * Hash password for storage (Argon2id)
 * 
 * @param password User password
 * @param password_len Length of password
 * @param hash_output Output encoded hash (128+ bytes)
 * @param hash_output_len Size of output buffer
 * @return 0 on success, negative on error
 */
int nextssl_password_hash(
    const char *password, size_t password_len,
    char *hash_output, size_t hash_output_len);

/**
 * Verify password (constant-time)
 * 
 * @param password User-entered password
 * @param password_len Length of password
 * @param stored_hash Hash from nextssl_password_hash()
 * @return 1 if match, 0 if mismatch, negative on error
 */
int nextssl_password_verify(
    const char *password, size_t password_len,
    const char *stored_hash);

/* ========== Key Exchange ========== */

/**
 * Generate key exchange keypair (X25519)
 * 
 * @param public_key Output public key (32 bytes)
 * @param secret_key Output secret key (32 bytes)
 * @return 0 on success, negative on error
 */
int nextssl_keyexchange_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32]);

/**
 * Compute shared secret (X25519)
 * 
 * @param shared_secret Output (32 bytes)
 * @param our_secret_key Our secret key
 * @param their_public_key Their public key
 * @return 0 on success, negative on error
 */
int nextssl_keyexchange_compute(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]);

/* ========== Digital Signatures ========== */

/**
 * Generate signature keypair (Ed25519)
 * 
 * @param public_key Output (32 bytes)
 * @param secret_key Output (64 bytes)
 * @return 0 on success, negative on error
 */
int nextssl_sign_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[64]);

/**
 * Sign message (Ed25519)
 * 
 * @param signature Output (64 bytes)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key
 * @return 0 on success, negative on error
 */
int nextssl_sign(
    uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t secret_key[64]);

/**
 * Verify signature (Ed25519)
 * 
 * @param signature Signature to verify
 * @param message Original message
 * @param message_len Length of message
 * @param public_key Signer's public key
 * @return 1 if valid, 0 if invalid, negative on error
 */
int nextssl_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[32]);

/* ========== Post-Quantum Cryptography ========== */

/**
 * Generate PQ keypair (ML-KEM-768)
 * 
 * @param public_key Output (1184 bytes)
 * @param secret_key Output (2400 bytes)
 * @return 0 on success, negative on error
 */
int nextssl_pq_kem_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * PQ encapsulate (ML-KEM-768)
 * 
 * @param ciphertext Output (1088 bytes)
 * @param shared_secret Output (32 bytes)
 * @param public_key Recipient's public key
 * @return 0 on success, negative on error
 */
int nextssl_pq_kem_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

/**
 * PQ decapsulate (ML-KEM-768)
 * 
 * @param shared_secret Output (32 bytes)
 * @param ciphertext Received ciphertext
 * @param secret_key Own secret key
 * @return 0 on success, negative on error
 */
int nextssl_pq_kem_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

/**
 * Generate PQ signature keypair (ML-DSA-65)
 * 
 * @param public_key Output (1952 bytes)
 * @param secret_key Output (4000 bytes)
 * @return 0 on success, negative on error
 */
int nextssl_pq_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Sign with PQ (ML-DSA-65)
 * 
 * @param signature Output (3293+ bytes)
 * @param signature_len Actual signature length
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key
 * @return 0 on success, negative on error
 */
int nextssl_pq_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key);

/**
 * Verify PQ signature (ML-DSA-65)
 * 
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param message Original message
 * @param message_len Length of message
 * @param public_key Signer's public key
 * @return 1 if valid, 0 if invalid, negative on error
 */
int nextssl_pq_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);

/* ========== Utility Functions ========== */

/**
 * Securely zero memory
 * 
 * @param data Buffer to zero
 * @param length Length of buffer
 */
void nextssl_secure_zero(void *data, size_t length);

/**
 * Constant-time comparison
 * 
 * @param a First buffer
 * @param b Second buffer
 * @param length Length to compare
 * @return 1 if equal, 0 if not
 */
int nextssl_constant_compare(
    const void *a, const void *b, size_t length);

/**
 * @brief Algorithm IDs for custom profiles
 *
 * These match the internal NEXTSSL_HASH_x/NEXTSSL_AEAD_x/... enum values.
 * Full variant accepts the complete set including legacy/extended IDs.
 */
#define NEXTSSL_HASH_ID_SHA256   0
#define NEXTSSL_HASH_ID_SHA512   1
#define NEXTSSL_HASH_ID_BLAKE3   2
#define NEXTSSL_HASH_ID_SHA384   3
#define NEXTSSL_HASH_ID_SHA1     4
#define NEXTSSL_HASH_ID_MD5      5
#define NEXTSSL_HASH_ID_BLAKE2B  6

#define NEXTSSL_AEAD_ID_AES256GCM        0
#define NEXTSSL_AEAD_ID_CHACHA20POLY1305 1
#define NEXTSSL_AEAD_ID_AES128GCM        2
#define NEXTSSL_AEAD_ID_AES256CCM        3
#define NEXTSSL_AEAD_ID_AEGIS256         5

#define NEXTSSL_KDF_ID_HKDF_SHA256  0
#define NEXTSSL_KDF_ID_ARGON2ID     1
#define NEXTSSL_KDF_ID_HKDF_SHA512  2
#define NEXTSSL_KDF_ID_ARGON2I      3
#define NEXTSSL_KDF_ID_SCRYPT       5
#define NEXTSSL_KDF_ID_PBKDF2       6

#define NEXTSSL_SIGN_ID_ED25519    0
#define NEXTSSL_SIGN_ID_ML_DSA_87  1
#define NEXTSSL_SIGN_ID_ML_DSA_65  3
#define NEXTSSL_SIGN_ID_ML_DSA_44  4
#define NEXTSSL_SIGN_ID_ECDSA_P256 8
#define NEXTSSL_SIGN_ID_RSA3072PSS 10

#define NEXTSSL_KEM_ID_X25519      0
#define NEXTSSL_KEM_ID_ML_KEM_1024 1
#define NEXTSSL_KEM_ID_ML_KEM_768  3
#define NEXTSSL_KEM_ID_ML_KEM_512  4

/**
 * @brief Custom profile descriptor — pass to nextssl_init_custom()
 *
 * Set each field to its algorithm ID constant above.
 * Config becomes immutable after nextssl_init_custom() returns 0.
 */
typedef struct {
    int hash;          /**< Hash algorithm ID */
    int aead;          /**< AEAD cipher ID */
    int kdf;           /**< Key derivation function ID */
    int sign;          /**< Signature algorithm ID */
    int kem;           /**< Key exchange/KEM algorithm ID */
    const char *name;  /**< Optional label (NULL = "Custom") */
} nextssl_custom_profile_t;

/* ========== Initialization & Testing ========== */

/**
 * Initialize NextSSL (optional, auto-called on first use)
 *
 * Profiles:
 *   0 = MODERN       (default: SHA-256 / AES-256-GCM / Ed25519 / X25519)
 *   1 = COMPLIANCE   (FIPS/NIST aligned)
 *   2 = PQC          (post-quantum)
 *   3 = COMPATIBILITY (includes legacy)
 *   4 = EMBEDDED     (ChaCha20-Poly1305, small footprint)
 *   5 = RESEARCH     (all algorithms, experimental)
 *
 * @param profile  Security profile index (0 = default MODERN)
 * @return 0 on success, negative on error
 */
int nextssl_init(int profile);

/**
 * @brief Initialize NextSSL with a fully custom algorithm profile
 *
 * Builds the config from the provided descriptor. All five fields must be
 * set. Rejects Algorithm IDs not compiled into this variant.
 * Config is immutable after a successful call.
 *
 * @param profile  Pointer to filled nextssl_custom_profile_t
 * @return 0 on success, -1 if profile is NULL, -2 if already initialized,
 *         -3 if any algorithm ID is invalid/unavailable in this build
 */
int nextssl_init_custom(const nextssl_custom_profile_t *profile);

/**
 * Run comprehensive self-tests
 * 
 * @return 0 if all tests pass, negative on failure
 */
int nextssl_selftest(void);

/**
 * Cleanup NextSSL resources (optional)
 */
void nextssl_cleanup(void);

#ifdef __cplusplus
}
#endif

/* Explicit-algorithm interface (bypasses profile dispatch) */
#include "root/nextssl_root.h"

#endif /* NEXTSSL_H */
