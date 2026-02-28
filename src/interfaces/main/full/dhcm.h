/**
 * @file dhcm.h
 * @brief Layer 3: High-level key exchange
 * @layer main
 * @category dhcm
 * @visibility public
 * 
 * Simple key exchange interface for establishing shared secrets.
 * 
 * **Default algorithm:** X25519 (classical security)
 * **Post-quantum option:** ML-KEM-768
 * 
 * @security Recommended for TLS-like protocols, secure messaging
 * @example Establish encrypted communication channel
 */

#ifndef NEXTSSL_MAIN_DHCM_H
#define NEXTSSL_MAIN_DHCM_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* Key sizes */
#define NEXTSSL_KEYEXCHANGE_PUBLIC_KEY_SIZE   32
#define NEXTSSL_KEYEXCHANGE_SECRET_KEY_SIZE   32
#define NEXTSSL_KEYEXCHANGE_SHARED_SECRET_SIZE 32

/* ========== X25519 Key Exchange (Default) ========== */

/**
 * Generate key exchange keypair (X25519)
 * 
 * @param public_key Output for public key (32 bytes)
 * @param secret_key Output for secret key (32 bytes, keep private!)
 * @return 0 on success, negative on error
 * 
 * @example Server/client generate keypair on startup
 */
NEXTSSL_MAIN_API int nextssl_keyexchange_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32]);

/**
 * Compute shared secret from peer's public key (X25519)
 * 
 * @param shared_secret Output for shared secret (32 bytes)
 * @param our_secret_key Our secret key from keypair()
 * @param their_public_key Their public key (received over network)
 * @return 0 on success, negative on error
 * 
 * @security Both parties derive the same shared secret
 * @example Use shared secret to derive encryption keys
 */
NEXTSSL_MAIN_API int nextssl_keyexchange_compute(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]);

/* ========== Post-Quantum Key Exchange ========== */

/* PQ key sizes */
#define NEXTSSL_PQ_KEYEXCHANGE_PUBLIC_KEY_SIZE   1184
#define NEXTSSL_PQ_KEYEXCHANGE_SECRET_KEY_SIZE   2400
#define NEXTSSL_PQ_KEYEXCHANGE_CIPHERTEXT_SIZE   1088
#define NEXTSSL_PQ_KEYEXCHANGE_SHARED_SECRET_SIZE 32

/**
 * Generate post-quantum keypair (ML-KEM-768)
 * 
 * @param public_key Output for public key (1184 bytes)
 * @param secret_key Output for secret key (2400 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Quantum-resistant (NIST FIPS 203)
 */
NEXTSSL_MAIN_API int nextssl_pq_keyexchange_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * Encapsulate shared secret (sender side, ML-KEM-768)
 * 
 * @param ciphertext Output for ciphertext (1088 bytes, send to peer)
 * @param shared_secret Output for shared secret (32 bytes, local use)
 * @param their_public_key Recipient's public key
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pq_keyexchange_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *their_public_key);

/**
 * Decapsulate shared secret (receiver side, ML-KEM-768)
 * 
 * @param shared_secret Output for shared secret (32 bytes)
 * @param ciphertext Received ciphertext from sender
 * @param our_secret_key Our secret key
 * @return 0 on success, negative on error
 */
NEXTSSL_MAIN_API int nextssl_pq_keyexchange_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *our_secret_key);

#endif /* NEXTSSL_MAIN_DHCM_H */
