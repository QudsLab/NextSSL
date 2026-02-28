/**
 * @file pqc.h
 * @brief Layer 3: High-level post-quantum cryptography
 * @layer main
 * @category pqc
 * @visibility public
 * 
 * Simplified post-quantum cryptography for quantum-resistant security.
 * 
 * **Algorithms:**
 * - ML-KEM-768: Key exchange (NIST FIPS 203)
 * - ML-DSA-65: Digital signatures (NIST FIPS 204)
 * 
 * @security Protects against quantum computer attacks
 * @recommendation Use for long-term security (10+ year horizon)
 */

#ifndef NEXTSSL_MAIN_PQC_H
#define NEXTSSL_MAIN_PQC_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* ========== Post-Quantum Key Exchange ========== */

/**
 * Generate PQ key exchange keypair
 * 
 * @param public_key Output buffer (1184 bytes)
 * @param secret_key Output buffer (2400 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pqc_kem_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Encapsulate shared secret (sender)
 * 
 * @param ciphertext Output buffer (1088 bytes)
 * @param shared_secret Output buffer (32 bytes)
 * @param public_key Recipient's public key
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pqc_kem_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

/**
 * Decapsulate shared secret (receiver)
 * 
 * @param shared_secret Output buffer (32 bytes)
 * @param ciphertext Received ciphertext
 * @param secret_key Own secret key
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pqc_kem_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

/* ========== Post-Quantum Digital Signatures ========== */

/**
 * Generate PQ signature keypair
 * 
 * @param public_key Output buffer (1952 bytes)
 * @param secret_key Output buffer (4000 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pqc_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Sign message
 * 
 * @param signature Output buffer (3293+ bytes)
 * @param signature_len Output for actual length
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pqc_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key);

/**
 * Verify signature
 * 
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param message Original message
 * @param message_len Length of message
 * @param public_key Signer's public key
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pqc_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);

#endif /* NEXTSSL_MAIN_PQC_H */
