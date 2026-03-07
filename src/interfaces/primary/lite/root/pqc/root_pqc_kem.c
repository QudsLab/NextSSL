/**
 * @file root/pqc/root_pqc_kem.c (Lite)
 * @brief NextSSL Root Lite -- ML-KEM-1024 implementation.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_pqc_kem.h"
#include "../../../../../PQCrypto/crypto_kem/ml-kem-1024/clean/api.h"

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_keygen(
    uint8_t pk[NEXTSSL_MLKEM1024_PK_BYTES],
    uint8_t sk[NEXTSSL_MLKEM1024_SK_BYTES]) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_encaps(
    const uint8_t pk[NEXTSSL_MLKEM1024_PK_BYTES],
    uint8_t ct[NEXTSSL_MLKEM1024_CT_BYTES],
    uint8_t ss[NEXTSSL_MLKEM1024_SS_BYTES]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_decaps(
    const uint8_t sk[NEXTSSL_MLKEM1024_SK_BYTES],
    const uint8_t ct[NEXTSSL_MLKEM1024_CT_BYTES],
    uint8_t ss[NEXTSSL_MLKEM1024_SS_BYTES]) {
    if (!sk || !ct || !ss) return -1;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}
