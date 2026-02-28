/**
 * @file sign.h
 * @brief Layer 2: Digital signature aggregation
 * @layer base
 * @category sign
 * @visibility semi-public
 * 
 * Digital signature algorithms for authentication and non-repudiation.
 * 
 * **Algorithms provided:**
 * - Ed25519 (recommended, EdDSA on Curve25519)
 * - ECDSA P-256 (NIST standard, widely compatible)
 * - ML-DSA-65 (post-quantum, future-proof)
 * 
 * @security ML-DSA-65 for quantum resistance, Ed25519 for classical security
 */

#ifndef NEXTSSL_BASE_SIGN_H
#define NEXTSSL_BASE_SIGN_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* Key/signature sizes */
#define NEXTSSL_ED25519_PUBLIC_KEY_SIZE   32
#define NEXTSSL_ED25519_SECRET_KEY_SIZE   64
#define NEXTSSL_ED25519_SIGNATURE_SIZE    64

#define NEXTSSL_ECDSA_P256_PUBLIC_KEY_SIZE  64
#define NEXTSSL_ECDSA_P256_SECRET_KEY_SIZE  32
#define NEXTSSL_ECDSA_P256_SIGNATURE_SIZE   64

#define NEXTSSL_ML_DSA_65_PUBLIC_KEY_SIZE   1952
#define NEXTSSL_ML_DSA_65_SECRET_KEY_SIZE   4000
#define NEXTSSL_ML_DSA_65_SIGNATURE_SIZE    3293

/* ========== Ed25519 (RECOMMENDED for classical crypto) ========== */

/**
 * Generate Ed25519 keypair
 * 
 * @param public_key Output for public key (32 bytes)
 * @param secret_key Output for secret key (64 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance RFC 8032
 * @security 128-bit security level
 */
NEXTSSL_BASE_API int nextssl_base_sign_ed25519_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[64]);

/**
 * Sign message with Ed25519
 * 
 * @param signature Output for signature (64 bytes)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key (64 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Deterministic signatures, collision-resistant
 */
NEXTSSL_BASE_API int nextssl_base_sign_ed25519_sign(
    uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t secret_key[64]);

/**
 * Verify Ed25519 signature
 * 
 * @param signature Signature to verify (64 bytes)
 * @param message Message that was signed
 * @param message_len Length of message
 * @param public_key Signer's public key (32 bytes)
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_sign_ed25519_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[32]);

/* ========== ECDSA P-256 (NIST standard) ========== */

/**
 * Generate ECDSA P-256 keypair
 * 
 * @param public_key Output for public key (64 bytes uncompressed)
 * @param secret_key Output for secret key (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance FIPS 186-4
 * @security 128-bit security level
 */
NEXTSSL_BASE_API int nextssl_base_sign_ecdsa_p256_keypair(
    uint8_t public_key[64],
    uint8_t secret_key[32]);

/**
 * Sign message with ECDSA P-256
 * 
 * @param signature Output for signature (64 bytes)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Randomized signatures for side-channel resistance
 */
NEXTSSL_BASE_API int nextssl_base_sign_ecdsa_p256_sign(
    uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t secret_key[32]);

/**
 * Verify ECDSA P-256 signature
 * 
 * @param signature Signature to verify (64 bytes)
 * @param message Message that was signed
 * @param message_len Length of message
 * @param public_key Signer's public key (64 bytes)
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_sign_ecdsa_p256_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[64]);

/* ========== ML-DSA-65 (Post-quantum) ========== */

/**
 * Generate ML-DSA-65 keypair
 * 
 * @param public_key Output for public key (1952 bytes)
 * @param secret_key Output for secret key (4000 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance NIST FIPS 204
 * @security 192-bit post-quantum security (Category 3)
 */
NEXTSSL_BASE_API int nextssl_base_sign_ml_dsa_65_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Sign message with ML-DSA-65
 * 
 * @param signature Output for signature (max 3293 bytes)
 * @param signature_len Output for actual signature length
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key (4000 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_sign_ml_dsa_65_sign(
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key);

/**
 * Verify ML-DSA-65 signature
 * 
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param message Message that was signed
 * @param message_len Length of message
 * @param public_key Signer's public key (1952 bytes)
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_sign_ml_dsa_65_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);

/**
 * Self-test for sign operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_sign_selftest(void);

#endif /* NEXTSSL_BASE_SIGN_H */
