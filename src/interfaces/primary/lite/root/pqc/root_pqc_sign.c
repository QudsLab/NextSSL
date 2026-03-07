/**
 * @file root/pqc/root_pqc_sign.c (Lite)
 * @brief NextSSL Root Lite -- ML-DSA-87 implementation.
 */

#ifndef NEXTSSL_BUILDING_DLL
#define NEXTSSL_BUILDING_DLL
#endif

#include "root_pqc_sign.h"
#include "../../../../../PQCrypto/crypto_sign/ml-dsa-87/clean/api.h"

NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_keygen(
    uint8_t pk[NEXTSSL_MLDSA87_PK_BYTES],
    uint8_t sk[NEXTSSL_MLDSA87_SK_BYTES]) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_sign(
    const uint8_t sk[NEXTSSL_MLDSA87_SK_BYTES],
    const uint8_t *msg, size_t mlen,
    uint8_t *sig, size_t *sig_len) {
    if (!sk || !sig || !sig_len) return -1;
    if (mlen > 0 && !msg) return -1;
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, sig_len, msg, mlen, sk)
           == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_pqc_sign_mldsa87_verify(
    const uint8_t pk[NEXTSSL_MLDSA87_PK_BYTES],
    const uint8_t *msg, size_t mlen,
    const uint8_t *sig, size_t sig_len) {
    if (!pk || !sig) return -1;
    if (mlen > 0 && !msg) return -1;
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, sig_len, msg, mlen, pk)
           == 0 ? 1 : 0;
}
