/**
 * @file root/pqc/root_pqc_kem.h (Lite)
 * @brief NextSSL Root Lite -- Explicit PQC KEM interface.
 *
 * Lite build provides: ML-KEM-1024 only.
 *
 * Algorithm sizes:
 *   ML-KEM-1024: pk = 1568 B, sk = 3168 B, ct = 1568 B, ss = 32 B
 *
 * @version 0.0.1-beta
 */

#ifndef NEXTSSL_LITE_ROOT_PQC_KEM_H
#define NEXTSSL_LITE_ROOT_PQC_KEM_H

#include <stddef.h>
#include <stdint.h>
#include "../../../../../config.h"  /* NEXTSSL_API */

#ifdef __cplusplus
extern "C" {
#endif

/* ML-KEM-1024 size constants */
#define NEXTSSL_MLKEM1024_PK_BYTES    1568
#define NEXTSSL_MLKEM1024_SK_BYTES    3168
#define NEXTSSL_MLKEM1024_CT_BYTES    1568
#define NEXTSSL_MLKEM1024_SS_BYTES      32

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_keygen(
    uint8_t pk[NEXTSSL_MLKEM1024_PK_BYTES],
    uint8_t sk[NEXTSSL_MLKEM1024_SK_BYTES]);

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_encaps(
    const uint8_t pk[NEXTSSL_MLKEM1024_PK_BYTES],
    uint8_t ct[NEXTSSL_MLKEM1024_CT_BYTES],
    uint8_t ss[NEXTSSL_MLKEM1024_SS_BYTES]);

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_decaps(
    const uint8_t sk[NEXTSSL_MLKEM1024_SK_BYTES],
    const uint8_t ct[NEXTSSL_MLKEM1024_CT_BYTES],
    uint8_t ss[NEXTSSL_MLKEM1024_SS_BYTES]);

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_LITE_ROOT_PQC_KEM_H */
