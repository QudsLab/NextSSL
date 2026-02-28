/**
 * @file signature_lite.h
 * @brief Lite variant digital signature API (Ed25519, Dilithium5 only)
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_MAIN_LITE_SIGNATURE_H
#define NEXTSSL_MAIN_LITE_SIGNATURE_H

#include "../../../config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key/signature sizes for Ed25519 (classical) */
#define NEXTSSL_LITE_ED25519_PUBLIC_KEY_SIZE   32
#define NEXTSSL_LITE_ED25519_SECRET_KEY_SIZE   64
#define NEXTSSL_LITE_ED25519_SIGNATURE_SIZE    64

/* Key/signature sizes for Dilithium5 (post-quantum) */
#define NEXTSSL_LITE_DILITHIUM5_PUBLIC_KEY_SIZE  2592
#define NEXTSSL_LITE_DILITHIUM5_SECRET_KEY_SIZE  4864
#define NEXTSSL_LITE_DILITHIUM5_SIGNATURE_SIZE   4627

/**
 * @brief Signature algorithms
 */
typedef enum {
    NEXTSSL_LITE_SIGN_ED25519,      /**< Ed25519 (EdDSA on Curve25519) */
    NEXTSSL_LITE_SIGN_DILITHIUM5    /**< Dilithium5 (NIST FIPS 204) */
} nextssl_lite_sign_algorithm_t;

/**
 * @brief Generate Ed25519 keypair
 * 
 * @param public_key Output public key (32 bytes)
 * @param secret_key Output secret key (64 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_ed25519_keygen(
    uint8_t public_key[NEXTSSL_LITE_ED25519_PUBLIC_KEY_SIZE],
    uint8_t secret_key[NEXTSSL_LITE_ED25519_SECRET_KEY_SIZE]
);

/**
 * @brief Sign message with Ed25519
 * 
 * @param message Message to sign
 * @param message_len Message length
 * @param secret_key Secret key (64 bytes)
 * @param signature Output signature (64 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_ed25519_sign(
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[NEXTSSL_LITE_ED25519_SECRET_KEY_SIZE],
    uint8_t signature[NEXTSSL_LITE_ED25519_SIGNATURE_SIZE]
);

/**
 * @brief Verify Ed25519 signature
 * 
 * @param message Message that was signed
 * @param message_len Message length
 * @param signature Signature to verify (64 bytes)
 * @param public_key Public key (32 bytes)
 * @return 0 if valid, negative if invalid
 * 
 * @retval 0 Signature is valid
 * @retval -NEXTSSL_ERROR_AUTH_FAILED Signature is invalid
 */
NEXTSSL_API int nextssl_lite_ed25519_verify(
    const uint8_t *message,
    size_t message_len,
    const uint8_t signature[NEXTSSL_LITE_ED25519_SIGNATURE_SIZE],
    const uint8_t public_key[NEXTSSL_LITE_ED25519_PUBLIC_KEY_SIZE]
);

/**
 * @brief Generate Dilithium5 keypair
 * 
 * @param public_key Output public key (2592 bytes)
 * @param secret_key Output secret key (4864 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_dilithium5_keygen(
    uint8_t public_key[NEXTSSL_LITE_DILITHIUM5_PUBLIC_KEY_SIZE],
    uint8_t secret_key[NEXTSSL_LITE_DILITHIUM5_SECRET_KEY_SIZE]
);

/**
 * @brief Sign message with Dilithium5
 * 
 * @param message Message to sign
 * @param message_len Message length
 * @param secret_key Secret key (4864 bytes)
 * @param signature Output signature (4627 bytes)
 * @param signature_len Output: actual signature length
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_dilithium5_sign(
    const uint8_t *message,
    size_t message_len,
    const uint8_t secret_key[NEXTSSL_LITE_DILITHIUM5_SECRET_KEY_SIZE],
    uint8_t signature[NEXTSSL_LITE_DILITHIUM5_SIGNATURE_SIZE],
    size_t *signature_len
);

/**
 * @brief Verify Dilithium5 signature
 * 
 * @param message Message that was signed
 * @param message_len Message length
 * @param signature Signature to verify
 * @param signature_len Signature length
 * @param public_key Public key (2592 bytes)
 * @return 0 if valid, negative if invalid
 * 
 * @retval 0 Signature is valid
 * @retval -NEXTSSL_ERROR_AUTH_FAILED Signature is invalid
 */
NEXTSSL_API int nextssl_lite_dilithium5_verify(
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len,
    const uint8_t public_key[NEXTSSL_LITE_DILITHIUM5_PUBLIC_KEY_SIZE]
);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_MAIN_LITE_SIGNATURE_H */
