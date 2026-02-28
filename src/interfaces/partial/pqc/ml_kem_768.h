/**
 * @file ml_kem_768.h
 * @brief ML-KEM-768 (NIST FIPS 203) - Security Category 3
 * @layer partial
 * @category pqc
 * @visibility hidden
 * 
 * ML-KEM-768 provides quantum security roughly equivalent to AES-192.
 * Recommended parameter set for most applications, balanced security/performance.
 * 
 * @compliance NIST FIPS 203 (formerly Kyber-768)
 * @security 192-bit post-quantum security (NIST Security Category 3)
 */

#ifndef NEXTSSL_PARTIAL_PQC_ML_KEM_768_H
#define NEXTSSL_PARTIAL_PQC_ML_KEM_768_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ML-KEM-768 parameters */
#define NEXTSSL_ML_KEM_768_PUBLIC_KEY_BYTES   1184
#define NEXTSSL_ML_KEM_768_SECRET_KEY_BYTES   2400
#define NEXTSSL_ML_KEM_768_CIPHERTEXT_BYTES   1088
#define NEXTSSL_ML_KEM_768_SHARED_SECRET_BYTES 32

/**
 * Generate ML-KEM-768 keypair
 * 
 * @param public_key Output buffer for public key (1184 bytes)
 * @param secret_key Output buffer for secret key (2400 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Requires cryptographically secure randomness
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_768_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Encapsulate shared secret (sender side)
 * 
 * @param ciphertext Output buffer for ciphertext (1088 bytes)
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param public_key Recipient's public key (1184 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_768_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

/**
 * Decapsulate shared secret (receiver side)
 * 
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param ciphertext Received ciphertext (1088 bytes)
 * @param secret_key Own secret key (2400 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Constant-time implementation resists side-channel attacks
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_768_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

/**
 * Self-test for ML-KEM-768 implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_768_selftest(void);

#endif /* NEXTSSL_PARTIAL_PQC_ML_KEM_768_H */
