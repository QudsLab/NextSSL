/**
 * @file pqc_lite.h
 * @brief Lite variant post-quantum cryptography unified API
 * @version 0.1.0-beta-lite
 * @date 2026-02-28
 */

#ifndef NEXTSSL_MAIN_LITE_PQC_H
#define NEXTSSL_MAIN_LITE_PQC_H

#include "../../../config.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Combined PQC operations (wrapper for keyexchange_lite and signature_lite)
 * 
 * This header provides a unified API for post-quantum cryptography,
 * combining Kyber1024 (KEM) and Dilithium5 (signatures).
 */

/* Re-export key sizes for convenience */
#define NEXTSSL_LITE_PQC_KEM_PUBLIC_SIZE   1568
#define NEXTSSL_LITE_PQC_KEM_SECRET_SIZE   3168
#define NEXTSSL_LITE_PQC_KEM_CT_SIZE       1568
#define NEXTSSL_LITE_PQC_KEM_SHARED_SIZE   32

#define NEXTSSL_LITE_PQC_SIGN_PUBLIC_SIZE  2592
#define NEXTSSL_LITE_PQC_SIGN_SECRET_SIZE  4864
#define NEXTSSL_LITE_PQC_SIGN_SIG_SIZE     4627

/**
 * @brief Generate combined PQC keypair (KEM + Sign)
 * 
 * Generates both Kyber1024 and Dilithium5 keypairs for full PQC capability
 * 
 * @param kem_public Output KEM public key (1568 bytes)
 * @param kem_secret Output KEM secret key (3168 bytes)
 * @param sign_public Output signature public key (2592 bytes)
 * @param sign_secret Output signature secret key (4864 bytes)
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_pqc_keygen_combined(
    uint8_t *kem_public,
    uint8_t *kem_secret,
    uint8_t *sign_public,
    uint8_t *sign_secret
);

/**
 * @brief Get PQC algorithm info
 * 
 * @param buffer Output buffer
 * @param size Buffer size
 * @return 0 on success
 */
NEXTSSL_API int nextssl_lite_pqc_info(char *buffer, size_t size);

/**
 * @brief Check if PQC is available in this build
 * 
 * @return 1 if PQC algorithms are available, 0 otherwise
 */
NEXTSSL_API int nextssl_lite_pqc_available(void);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_MAIN_LITE_PQC_H */
