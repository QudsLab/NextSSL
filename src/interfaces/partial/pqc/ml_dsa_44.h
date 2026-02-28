/**
 * @file ml_dsa_44.h
 * @brief ML-DSA-44 (NIST FIPS 204) - Security Category 2
 * @layer partial
 * @category pqc
 * @visibility hidden
 * 
 * ML-DSA-44 provides quantum-resistant digital signatures roughly equivalent
 * to 128-bit classical security. Smallest parameter set, suitable for
 * constrained environments.
 * 
 * @compliance NIST FIPS 204 (formerly Dilithium2)
 * @security 128-bit post-quantum security (NIST Security Category 2)
 */

#ifndef NEXTSSL_PARTIAL_PQC_ML_DSA_44_H
#define NEXTSSL_PARTIAL_PQC_ML_DSA_44_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ML-DSA-44 parameters */
#define NEXTSSL_ML_DSA_44_PUBLIC_KEY_BYTES   1312
#define NEXTSSL_ML_DSA_44_SECRET_KEY_BYTES   2528
#define NEXTSSL_ML_DSA_44_SIGNATURE_BYTES    2420

/**
 * Generate ML-DSA-44 keypair
 * 
 * @param public_key Output buffer for public key (1312 bytes)
 * @param secret_key Output buffer for secret key (2528 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Requires cryptographically secure randomness
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_44_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Sign message with ML-DSA-44
 * 
 * @param signature Output buffer for signature (2420 bytes)
 * @param signature_len Output for actual signature length (may be variable)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key (2528 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Signature includes randomness for security against side-channels
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_44_sign(
    uint8_t *signature,
    size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key);

/**
 * Verify ML-DSA-44 signature
 * 
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param message Message that was signed
 * @param message_len Length of message
 * @param public_key Signer's public key (1312 bytes)
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_44_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);

/**
 * Self-test for ML-DSA-44 implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_44_selftest(void);

#endif /* NEXTSSL_PARTIAL_PQC_ML_DSA_44_H */
