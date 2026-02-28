/**
 * @file pqc.h
 * @brief Layer 2: Post-quantum cryptography aggregation
 * @layer base
 * @category pqc
 * @visibility semi-public
 * 
 * NIST-standardized post-quantum algorithms for quantum-resistant security.
 * 
 * **Algorithms provided:**
 * - ML-KEM-768 (key encapsulation, recommended)
 * - ML-DSA-65 (digital signatures, recommended)
 * 
 * @compliance NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA)
 * @security Protects against quantum computer attacks
 */

#ifndef NEXTSSL_BASE_PQC_H
#define NEXTSSL_BASE_PQC_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ML-KEM-768 (recommended parameter set) */
#define NEXTSSL_ML_KEM_768_PUBLIC_KEY_BYTES   1184
#define NEXTSSL_ML_KEM_768_SECRET_KEY_BYTES   2400
#define NEXTSSL_ML_KEM_768_CIPHERTEXT_BYTES   1088
#define NEXTSSL_ML_KEM_768_SHARED_SECRET_BYTES 32

/* ML-DSA-65 (recommended parameter set) */
#define NEXTSSL_ML_DSA_65_PUBLIC_KEY_BYTES    1952
#define NEXTSSL_ML_DSA_65_SECRET_KEY_BYTES    4000
#define NEXTSSL_ML_DSA_65_SIGNATURE_BYTES     3293

/* ========== ML-KEM-768 Key Encapsulation ========== */

/**
 * Generate ML-KEM-768 keypair
 * 
 * @param public_key Output for public key (1184 bytes)
 * @param secret_key Output for secret key (2400 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pqc_kem_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Encapsulate shared secret
 * 
 * @param ciphertext Output for ciphertext (1088 bytes)
 * @param shared_secret Output for shared secret (32 bytes)
 * @param public_key Recipient's public key (1184 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pqc_kem_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

/**
 * Decapsulate shared secret
 * 
 * @param shared_secret Output for shared secret (32 bytes)
 * @param ciphertext Received ciphertext (1088 bytes)
 * @param secret_key Own secret key (2400 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pqc_kem_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

/* ========== ML-DSA-65 Digital Signatures ========== */

/**
 * Generate ML-DSA-65 keypair
 * 
 * @param public_key Output for public key (1952 bytes)
 * @param secret_key Output for secret key (4000 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pqc_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Sign message
 * 
 * @param signature Output for signature (3293 bytes)
 * @param signature_len Output for actual signature length
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key (4000 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pqc_sign(
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key);

/**
 * Verify signature
 * 
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param message Message that was signed
 * @param message_len Length of message
 * @param public_key Signer's public key (1952 bytes)
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_pqc_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);

/**
 * Self-test for PQC operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_pqc_selftest(void);

#endif /* NEXTSSL_BASE_PQC_H */
