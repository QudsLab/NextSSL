/**
 * @file dhcm.h
 * @brief Layer 2: Diffie-Hellman and key exchange aggregation
 * @layer base
 * @category dhcm
 * @visibility semi-public
 * 
 * Key exchange mechanisms for establishing shared secrets.
 * 
 * **Algorithms provided:**
 * - X25519 (recommended, fastest, 128-bit security)
 * - X448 (high security, 224-bit security)
 * - ML-KEM-768 (post-quantum, recommended for future-proofing)
 * - ECDH P-256 (NIST standard, widely compatible)
 * 
 * @security Use ML-KEM for post-quantum security, X25519 for classical security
 */

#ifndef NEXTSSL_BASE_DHCM_H
#define NEXTSSL_BASE_DHCM_H

#include "../visibility.h"
#include <stddef.h>
#include <stdint.h>

/* Key sizes */
#define NEXTSSL_X25519_KEY_SIZE    32
#define NEXTSSL_X448_KEY_SIZE      56
#define NEXTSSL_P256_KEY_SIZE      32
#define NEXTSSL_ML_KEM_768_PUBLIC_KEY_SIZE  1184
#define NEXTSSL_ML_KEM_768_SECRET_KEY_SIZE  2400
#define NEXTSSL_ML_KEM_768_CIPHERTEXT_SIZE  1088
#define NEXTSSL_ML_KEM_768_SHARED_SECRET_SIZE 32

/* ========== X25519 (RECOMMENDED for classical crypto) ========== */

/**
 * Generate X25519 keypair
 * 
 * @param public_key Output buffer for public key (32 bytes)
 * @param secret_key Output buffer for secret key (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance RFC 7748
 * @security 128-bit security level
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_x25519_keypair(
    uint8_t public_key[32],
    uint8_t secret_key[32]);

/**
 * Perform X25519 key exchange
 * 
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param our_secret_key Our secret key (32 bytes)
 * @param their_public_key Their public key (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @security Rejects low-order points
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_x25519_exchange(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[32]);

/* ========== X448 (High security) ========== */

/**
 * Generate X448 keypair
 * 
 * @param public_key Output buffer for public key (56 bytes)
 * @param secret_key Output buffer for secret key (56 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance RFC 7748
 * @security 224-bit security level
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_x448_keypair(
    uint8_t public_key[56],
    uint8_t secret_key[56]);

/**
 * Perform X448 key exchange
 * 
 * @param shared_secret Output buffer for shared secret (56 bytes)
 * @param our_secret_key Our secret key (56 bytes)
 * @param their_public_key Their public key (56 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_x448_exchange(
    uint8_t shared_secret[56],
    const uint8_t our_secret_key[56],
    const uint8_t their_public_key[56]);

/* ========== ML-KEM-768 (Post-quantum recommended) ========== */

/**
 * Generate ML-KEM-768 keypair
 * 
 * @param public_key Output buffer for public key (1184 bytes)
 * @param secret_key Output buffer for secret key (2400 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance NIST FIPS 203
 * @security 192-bit post-quantum security (Category 3)
 * @note Recommended parameter set for most applications
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_ml_kem_768_keypair(
    uint8_t *public_key,
    uint8_t *secret_key);

/**
 * ML-KEM-768 encapsulation (sender side)
 * 
 * @param ciphertext Output buffer for ciphertext (1088 bytes)
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param public_key Recipient's public key (1184 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_ml_kem_768_encapsulate(
    uint8_t *ciphertext,
    uint8_t *shared_secret,
    const uint8_t *public_key);

/**
 * ML-KEM-768 decapsulation (receiver side)
 * 
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param ciphertext Received ciphertext (1088 bytes)
 * @param secret_key Own secret key (2400 bytes)
 * @return 0 on success, negative on error
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_ml_kem_768_decapsulate(
    uint8_t *shared_secret,
    const uint8_t *ciphertext,
    const uint8_t *secret_key);

/* ========== ECDH P-256 (NIST standard) ========== */

/**
 * Generate P-256 ECDH keypair
 * 
 * @param public_key Output buffer for public key (64 bytes uncompressed)
 * @param secret_key Output buffer for secret key (32 bytes)
 * @return 0 on success, negative on error
 * 
 * @compliance NIST SP 800-56A
 * @security 128-bit security level
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_p256_keypair(
    uint8_t public_key[64],
    uint8_t secret_key[32]);

/**
 * Perform P-256 ECDH key exchange
 * 
 * @param shared_secret Output buffer for shared secret (32 bytes)
 * @param our_secret_key Our secret key (32 bytes)
 * @param their_public_key Their public key (64 bytes uncompressed)
 * @return 0 on success, negative on error
 * 
 * @security Validates public key is on curve
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_p256_exchange(
    uint8_t shared_secret[32],
    const uint8_t our_secret_key[32],
    const uint8_t their_public_key[64]);

/**
 * Self-test for DHCM operations
 * @return 0 if all tests pass, negative on failure
 */
NEXTSSL_BASE_API int nextssl_base_dhcm_selftest(void);

#endif /* NEXTSSL_BASE_DHCM_H */
