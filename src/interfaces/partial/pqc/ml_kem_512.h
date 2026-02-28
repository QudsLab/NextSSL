/**
 * @file ml_kem_512.h
 * @brief ML-KEM-512 (NIST FIPS 203) - Security Category 1
 * @layer partial
 * @category pqc
 * @visibility hidden
 * 
 * ML-KEM-512 provides quantum security roughly equivalent to AES-128.
 * Smallest parameter set, fastest operations, suitable for constrained environments.
 * 
 * @compliance NIST FIPS 203 (formerly Kyber-512)
 * @security 128-bit post-quantum security (NIST Security Category 1)
 */

#ifndef NEXTSSL_PARTIAL_PQC_ML_KEM_512_H
#define NEXTSSL_PARTIAL_PQC_ML_KEM_512_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ML-KEM-512 parameters */
#define NEXTSSL_ML_KEM_512_PUBLIC_KEY_BYTES   800
#define NEXTSSL_ML_KEM_512_SECRET_KEY_BYTES   1632
#define NEXTSSL_ML_KEM_512_CIPHERTEXT_BYTES   768
#define NEXTSSL_ML_KEM_512_SHARED_SECRET_BYTES 32

/**
 * Generate ML-KEM-512 keypair
 * 
 * @param public_key Output buffer for public key (800 bytes)
 * @param secret_key Output buffer for secret key (1632 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Requires cryptographically secure randomness
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_512_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Encapsulate shared secret (sender side)
 * 
 * @param ciphertext Output buffer for ciphertext (768 bytes)
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param public_key Recipient's public key (800 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_512_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

/**
 * Decapsulate shared secret (receiver side)
 * 
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param ciphertext Received ciphertext (768 bytes)
 * @param secret_key Own secret key (1632 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Constant-time implementation resists side-channel attacks
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_512_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

/**
 * Self-test for ML-KEM-512 implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_kem_512_selftest(void);

#endif /* NEXTSSL_PARTIAL_PQC_ML_KEM_512_H */
