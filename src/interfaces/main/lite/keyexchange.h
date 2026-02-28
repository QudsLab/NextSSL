/**
 * @file keyexchange_lite.h
 * @brief Lite variant key exchange API (X25519, Kyber1024 only)
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_MAIN_LITE_KEYEXCHANGE_H
#define NEXTSSL_MAIN_LITE_KEYEXCHANGE_H

#include "../../../config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key sizes for X25519 (classical) */
#define NEXTSSL_LITE_X25519_PUBLIC_KEY_SIZE  32
#define NEXTSSL_LITE_X25519_SECRET_KEY_SIZE  32
#define NEXTSSL_LITE_X25519_SHARED_SIZE      32

/* Key sizes for Kyber1024 (post-quantum) */
#define NEXTSSL_LITE_KYBER1024_PUBLIC_KEY_SIZE  1568
#define NEXTSSL_LITE_KYBER1024_SECRET_KEY_SIZE  3168
#define NEXTSSL_LITE_KYBER1024_CIPHERTEXT_SIZE  1568
#define NEXTSSL_LITE_KYBER1024_SHARED_SIZE      32

/**
 * @brief Key exchange algorithms
 */
typedef enum {
    NEXTSSL_LITE_KEX_X25519,      /**< X25519 ECDH (Curve25519) */
    NEXTSSL_LITE_KEX_KYBER1024    /**< Kyber1024 KEM (NIST FIPS 203) */
} nextssl_lite_kex_algorithm_t;

/**
 * @brief Generate X25519 keypair
 * 
 * @param public_key Output public key (32 bytes)
 * @param secret_key Output secret key (32 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_x25519_keygen(
    uint8_t public_key[NEXTSSL_LITE_X25519_PUBLIC_KEY_SIZE],
    uint8_t secret_key[NEXTSSL_LITE_X25519_SECRET_KEY_SIZE]
);

/**
 * @brief Perform X25519 key exchange
 * 
 * @param my_secret My secret key (32 bytes)
 * @param their_public Their public key (32 bytes)
 * @param shared_secret Output shared secret (32 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_x25519_exchange(
    const uint8_t my_secret[NEXTSSL_LITE_X25519_SECRET_KEY_SIZE],
    const uint8_t their_public[NEXTSSL_LITE_X25519_PUBLIC_KEY_SIZE],
    uint8_t shared_secret[NEXTSSL_LITE_X25519_SHARED_SIZE]
);

/**
 * @brief Generate Kyber1024 keypair
 * 
 * @param public_key Output public key (1568 bytes)
 * @param secret_key Output secret key (3168 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_kyber1024_keygen(
    uint8_t public_key[NEXTSSL_LITE_KYBER1024_PUBLIC_KEY_SIZE],
    uint8_t secret_key[NEXTSSL_LITE_KYBER1024_SECRET_KEY_SIZE]
);

/**
 * @brief Kyber1024 encapsulation (sender side)
 * 
 * @param their_public Recipient's public key (1568 bytes)
 * @param ciphertext Output ciphertext (1568 bytes)
 * @param shared_secret Output shared secret (32 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_kyber1024_encaps(
    const uint8_t their_public[NEXTSSL_LITE_KYBER1024_PUBLIC_KEY_SIZE],
    uint8_t ciphertext[NEXTSSL_LITE_KYBER1024_CIPHERTEXT_SIZE],
    uint8_t shared_secret[NEXTSSL_LITE_KYBER1024_SHARED_SIZE]
);

/**
 * @brief Kyber1024 decapsulation (receiver side)
 * 
 * @param ciphertext Received ciphertext (1568 bytes)
 * @param my_secret My secret key (3168 bytes)
 * @param shared_secret Output shared secret (32 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_kyber1024_decaps(
    const uint8_t ciphertext[NEXTSSL_LITE_KYBER1024_CIPHERTEXT_SIZE],
    const uint8_t my_secret[NEXTSSL_LITE_KYBER1024_SECRET_KEY_SIZE],
    uint8_t shared_secret[NEXTSSL_LITE_KYBER1024_SHARED_SIZE]
);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_MAIN_LITE_KEYEXCHANGE_H */
