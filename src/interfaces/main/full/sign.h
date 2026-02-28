/**
 * @file sign.h
 * @brief Layer 3: High-level digital signatures
 * @layer main
 * @category sign
 * @visibility public
 * 
 * Simple digital signature interface for authentication.
 * 
 * **Default algorithm:** Ed25519 (classical security)
 * **Post-quantum option:** ML-DSA-65
 * 
 * @security Non-repudiation, authenticity, integrity
 * @example Code signing, message authentication, certificate authorities
 */

#ifndef NEXTSSL_MAIN_SIGN_H
#define NEXTSSL_MAIN_SIGN_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* Signature sizes */
#define NEXTSSL_SIGNATURE_PUBLIC_KEY_SIZE   32
#define NEXTSSL_SIGNATURE_SECRET_KEY_SIZE   64
#define NEXTSSL_SIGNATURE_SIZE              64

/* ========== Ed25519 Signatures (Default) ========== */

/**
 * Generate signature keypair (Ed25519)
 * 
 * @param public_key Output for public key (32 bytes, share publicly)
 * @param secret_key Output for secret key (64 bytes, keep private!)
 * @return 0 on success, negative on error
 * 
 * @example Generate signing key for code signing, certificates
 */
NEXTSSL_MAIN_API int nextssl_sign_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[64]);

/**
 * Sign message (Ed25519)
 * 
 * @param signature Output for signature (64 bytes)
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key
 * @return 0 on success, negative on error
 * 
 * @example Sign software release, API request, email
 */
NEXTSSL_MAIN_API int nextssl_sign(
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
 * 
 * @example Verify software authenticity, API authentication
 */
NEXTSSL_MAIN_API int nextssl_verify(
    const uint8_t signature[64],
    const uint8_t *message, size_t message_len,
    const uint8_t public_key[32]);

/* ========== Post-Quantum Signatures ========== */

/* PQ signature sizes */
#define NEXTSSL_PQ_SIGNATURE_PUBLIC_KEY_SIZE   1952
#define NEXTSSL_PQ_SIGNATURE_SECRET_KEY_SIZE   4000
#define NEXTSSL_PQ_SIGNATURE_MAX_SIZE          3293

/**
 * Generate post-quantum signature keypair (ML-DSA-65)
 * 
 * @param public_key Output for public key (1952 bytes)
 * @param secret_key Output for secret key (4000 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Quantum-resistant (NIST FIPS 204)
 */
NEXTSSL_MAIN_API int nextssl_pq_sign_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Sign message with post-quantum algorithm (ML-DSA-65)
 * 
 * @param signature Output for signature (buffer must be 3293+ bytes)
 * @param signature_len Output for actual signature length
 * @param message Message to sign
 * @param message_len Length of message
 * @param secret_key Signer's secret key
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pq_sign(
    uint8_t *signature, size_t *signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *secret_key);

/**
 * Verify post-quantum signature (ML-DSA-65)
 * 
 * @param signature Signature to verify
 * @param signature_len Length of signature
 * @param message Original message
 * @param message_len Length of message
 * @param public_key Signer's public key
 * @return 1 if valid, 0 if invalid, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pq_verify(
    const uint8_t *signature, size_t signature_len,
    const uint8_t *message, size_t message_len,
    const uint8_t *public_key);

#endif /* NEXTSSL_MAIN_SIGN_H */
