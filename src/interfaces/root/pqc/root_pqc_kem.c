/**
 * @file root/pqc/root_pqc_kem.c
 * @brief NextSSL Root — Post-quantum KEM implementation (all algorithms).
 */

#include "root_pqc_kem.h"
#include "../root_internal.h"

/* ML-KEM */
#ifndef NEXTSSL_BUILD_LITE
#include "../../../PQCrypto/crypto_kem/ml-kem-512/clean/api.h"
#include "../../../PQCrypto/crypto_kem/ml-kem-768/clean/api.h"
#endif /* NEXTSSL_BUILD_LITE */
#include "../../../PQCrypto/crypto_kem/ml-kem-1024/clean/api.h"

/* HQC + Classic McEliece (full build only) */
#ifndef NEXTSSL_BUILD_LITE
#include "../../../PQCrypto/crypto_kem/hqc-128/clean/api.h"
#include "../../../PQCrypto/crypto_kem/hqc-192/clean/api.h"
#include "../../../PQCrypto/crypto_kem/hqc-256/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece348864/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece348864f/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece460896/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece460896f/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece6688128/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece6688128f/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece6960119/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece6960119f/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece8192128/clean/api.h"
#include "../../../PQCrypto/crypto_kem/mceliece8192128f/clean/api.h"
#endif /* NEXTSSL_BUILD_LITE */

/* =========================================================================
 * ML-KEM
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE
NEXTSSL_API int nextssl_root_pqc_kem_mlkem512_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_mlkem512_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_mlkem512_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]) {
    if (!ct || !sk || !ss) return -1;
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_pqc_kem_mlkem768_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_mlkem768_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_mlkem768_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]) {
    if (!ct || !sk || !ss) return -1;
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}
#endif /* NEXTSSL_BUILD_LITE */

NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[32]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_mlkem1024_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[32]) {
    if (!ct || !sk || !ss) return -1;
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}

/* =========================================================================
 * HQC
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE

NEXTSSL_API int nextssl_root_pqc_kem_hqc128_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_hqc128_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[64]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_hqc128_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[64]) {
    if (!ct || !sk || !ss) return -1;
    return PQCLEAN_HQC128_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_pqc_kem_hqc192_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_hqc192_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[64]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_hqc192_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[64]) {
    if (!ct || !sk || !ss) return -1;
    return PQCLEAN_HQC192_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}

NEXTSSL_API int nextssl_root_pqc_kem_hqc256_keygen(uint8_t *pk, uint8_t *sk) {
    if (!pk || !sk) return -1;
    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_hqc256_encaps(const uint8_t *pk, uint8_t *ct, uint8_t ss[64]) {
    if (!pk || !ct || !ss) return -1;
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;
}
NEXTSSL_API int nextssl_root_pqc_kem_hqc256_decaps(const uint8_t *ct, const uint8_t *sk, uint8_t ss[64]) {
    if (!ct || !sk || !ss) return -1;
    return PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;
}

/* =========================================================================
 * Classic McEliece — macro to reduce boilerplate
 * ====================================================================== */

#define MCELIECE_IMPL(VARIANT, PREFIX)                                              \
NEXTSSL_API int nextssl_root_pqc_kem_##VARIANT##_keygen(uint8_t *pk, uint8_t *sk) { \
    if (!pk || !sk) return -1;                                                      \
    return PREFIX##_crypto_kem_keypair(pk, sk) == 0 ? 0 : -1;                      \
}                                                                                   \
NEXTSSL_API int nextssl_root_pqc_kem_##VARIANT##_encaps(const uint8_t *pk,         \
        uint8_t *ct, uint8_t ss[32]) {                                              \
    if (!pk || !ct || !ss) return -1;                                               \
    return PREFIX##_crypto_kem_enc(ct, ss, pk) == 0 ? 0 : -1;                      \
}                                                                                   \
NEXTSSL_API int nextssl_root_pqc_kem_##VARIANT##_decaps(const uint8_t *ct,         \
        const uint8_t *sk, uint8_t ss[32]) {                                        \
    if (!ct || !sk || !ss) return -1;                                               \
    return PREFIX##_crypto_kem_dec(ss, ct, sk) == 0 ? 0 : -1;                      \
}

MCELIECE_IMPL(mceliece348864,   PQCLEAN_MCELIECE348864_CLEAN)
MCELIECE_IMPL(mceliece348864f,  PQCLEAN_MCELIECE348864F_CLEAN)
MCELIECE_IMPL(mceliece460896,   PQCLEAN_MCELIECE460896_CLEAN)
MCELIECE_IMPL(mceliece460896f,  PQCLEAN_MCELIECE460896F_CLEAN)
MCELIECE_IMPL(mceliece6688128,  PQCLEAN_MCELIECE6688128_CLEAN)
MCELIECE_IMPL(mceliece6688128f, PQCLEAN_MCELIECE6688128F_CLEAN)
MCELIECE_IMPL(mceliece6960119,  PQCLEAN_MCELIECE6960119_CLEAN)
MCELIECE_IMPL(mceliece6960119f, PQCLEAN_MCELIECE6960119F_CLEAN)
MCELIECE_IMPL(mceliece8192128,  PQCLEAN_MCELIECE8192128_CLEAN)
MCELIECE_IMPL(mceliece8192128f, PQCLEAN_MCELIECE8192128F_CLEAN)

#undef MCELIECE_IMPL

#endif /* NEXTSSL_BUILD_LITE */
