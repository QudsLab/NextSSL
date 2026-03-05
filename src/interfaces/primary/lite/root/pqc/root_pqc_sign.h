/**
 * @file root/pqc/root_pqc_sign.h (Lite)
 * @brief NextSSL Root Lite -- Explicit PQC signature interface.
 *
 * Lite build provides: ML-DSA-87 only.
 *
 * Algorithm sizes:
 *   ML-DSA-87: pk = 2592 B, sk = 4896 B, sig = 4595 B (max)
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_PQC_SIGN_H
#define NEXTSSL_LITE_ROOT_PQC_SIGN_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"  /* NEXTSSL_API */

#ifdef __cplusplus
extern "C" {
#endif

/* ML-DSA-87 size constants */
#define NEXTSSL_MLDSA87_PK_BYTES     2592
#define NEXTSSL_MLDSA87_SK_BYTES     4896
#define NEXTSSL_MLDSA87_SIG_BYTES    4595

NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_keygen(
    uint8_t pk[NEXTSSL_MLDSA87_PK_BYTES],
    uint8_t sk[NEXTSSL_MLDSA87_SK_BYTES]);

NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_sign(
    const uint8_t sk[NEXTSSL_MLDSA87_SK_BYTES],
    const uint8_t *msg, size_t mlen,
    uint8_t *sig, size_t *sig_len);

/**
 * Verify ML-DSA-87 signature.
 * @return 1 if valid, 0 if invalid, <0 on error
 */
NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_verify(
    const uint8_t pk[NEXTSSL_MLDSA87_PK_BYTES],
    const uint8_t *msg, size_t mlen,
    const uint8_t *sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_ROOT_PQC_SIGN_H */
