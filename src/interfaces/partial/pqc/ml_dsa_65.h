/**
 * @file ml_dsa_65.h
 * @brief ML-DSA-65 (NIST FIPS 204) - Security Category 3
 * @layer partial
 * @category pqc
 * @visibility hidden
 * 
 * ML-DSA-65 provides quantum-resistant digital signatures roughly equivalent
 * to 192-bit classical security. Recommended parameter set for most applications.
 * 
 * @compliance NIST FIPS 204 (formerly Dilithium3)
 * @security 192-bit post-quantum security (NIST Security Category 3)
 */

#ifndef NEXTSSL_PARTIAL_PQC_ML_DSA_65_H
#define NEXTSSL_PARTIAL_PQC_ML_DSA_65_H

#include "../../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ML-DSA-65 parameters */
#define NEXTSSL_ML_DSA_65_PUBLIC_KEY_BYTES   1952
#define NEXTSSL_ML_DSA_65_SECRET_KEY_BYTES   4000
#define NEXTSSL_ML_DSA_65_SIGNATURE_BYTES    3293

/**
 * Generate ML-DSA-65 keypair
 * 
 * @param public_key Output buffer for public key (1952 bytes)
 * @param secret_key Output buffer for secret key (4000 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Requires cryptographically secure randomness
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_65_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Sign message with ML-DSA-65
 * 
 * @param signature Output buffer for signature (3293 bytes)
 * @param signature_len Output for actual signature length (may be variable)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key (4000 bytes)
 * @return 0 on success, negative on error
 * 
 * @note Signature includes randomness for security against side-channels
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_65_sign(
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
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_65_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);

/**
 * Self-test for ML-DSA-65 implementation
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_PARTIAL_API int nextssl_partial_pqc_ml_dsa_65_selftest(void);

#endif /* NEXTSSL_PARTIAL_PQC_ML_DSA_65_H */
