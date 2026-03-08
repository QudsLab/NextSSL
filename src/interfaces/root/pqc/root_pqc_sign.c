/**
 * @file root/pqc/root_pqc_sign.c
 * @brief NextSSL Root — Post-quantum signature implementation (all algorithms).
 */

#include "root_pqc_sign.h"
#include "../root_internal.h"

/* ML-DSA */
#ifndef NEXTSSL_BUILD_LITE
#include "../../../PQCrypto/crypto_sign/ml-dsa-44/clean/api.h"
#include "../../../PQCrypto/crypto_sign/ml-dsa-65/clean/api.h"
#endif /* NEXTSSL_BUILD_LITE */
#include "../../../PQCrypto/crypto_sign/ml-dsa-87/clean/api.h"

/* Falcon + SPHINCS+ (full only) */
#ifndef NEXTSSL_BUILD_LITE
#include "../../../PQCrypto/crypto_sign/falcon-512/clean/api.h"
#include "../../../PQCrypto/crypto_sign/falcon-1024/clean/api.h"
#include "../../../PQCrypto/crypto_sign/falcon-padded-512/clean/api.h"
#include "../../../PQCrypto/crypto_sign/falcon-padded-1024/clean/api.h"

/* SPHINCS+-SHA2 */
#include "../../../PQCrypto/crypto_sign/sphincs-sha2-128f-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-sha2-128s-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-sha2-192f-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-sha2-192s-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-sha2-256f-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-sha2-256s-simple/clean/api.h"

/* SPHINCS+-SHAKE */
#include "../../../PQCrypto/crypto_sign/sphincs-shake-128f-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-shake-128s-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-shake-192f-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-shake-192s-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-shake-256f-simple/clean/api.h"
#include "../../../PQCrypto/crypto_sign/sphincs-shake-256s-simple/clean/api.h"
#endif /* NEXTSSL_BUILD_LITE */

/* =========================================================================
 * Helper macro — generates all three functions per algorithm.
 * verify returns 1 valid, 0 invalid.
 * ====================================================================== */

#define SIGN_IMPL(NAME, PREFIX)                                                           \
NEXTSSL_API int nextssl_root_pqc_sign_##NAME##_keygen(uint8_t *pk, uint8_t *sk) {        \
    if (!pk || !sk) return -1;                                                            \
    return PREFIX##_crypto_sign_keypair(pk, sk) == 0 ? 0 : -1;                           \
}                                                                                         \
NEXTSSL_API int nextssl_root_pqc_sign_##NAME##_sign(uint8_t *sig, size_t *sig_len,       \
        const uint8_t *msg, size_t msg_len, const uint8_t *sk) {                          \
    if (!sig || !sig_len || !msg || !sk) return -1;                                       \
    return PREFIX##_crypto_sign_signature(sig, sig_len, msg, msg_len, sk) == 0 ? 0 : -1; \
}                                                                                         \
NEXTSSL_API int nextssl_root_pqc_sign_##NAME##_verify(const uint8_t *sig, size_t sig_len,\
        const uint8_t *msg, size_t msg_len, const uint8_t *pk) {                          \
    if (!sig || !msg || !pk) return -1;                                                   \
    return PREFIX##_crypto_sign_verify(sig, sig_len, msg, msg_len, pk) == 0 ? 1 : 0;     \
}

/* =========================================================================
 * ML-DSA
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE
SIGN_IMPL(mldsa44, PQCLEAN_MLDSA44_CLEAN)
SIGN_IMPL(mldsa65, PQCLEAN_MLDSA65_CLEAN)
#endif /* NEXTSSL_BUILD_LITE */
SIGN_IMPL(mldsa87, PQCLEAN_MLDSA87_CLEAN)

/* =========================================================================
 * Falcon
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE

SIGN_IMPL(falcon512,     PQCLEAN_FALCON512_CLEAN)
SIGN_IMPL(falcon1024,    PQCLEAN_FALCON1024_CLEAN)
SIGN_IMPL(falconpad512,  PQCLEAN_FALCONPADDED512_CLEAN)
SIGN_IMPL(falconpad1024, PQCLEAN_FALCONPADDED1024_CLEAN)

/* =========================================================================
 * SPHINCS+-SHA2
 * ====================================================================== */

SIGN_IMPL(sphincs_sha2_128f, PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN)
SIGN_IMPL(sphincs_sha2_128s, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN)
SIGN_IMPL(sphincs_sha2_192f, PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN)
SIGN_IMPL(sphincs_sha2_192s, PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN)
SIGN_IMPL(sphincs_sha2_256f, PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN)
SIGN_IMPL(sphincs_sha2_256s, PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN)

/* =========================================================================
 * SPHINCS+-SHAKE
 * ====================================================================== */

SIGN_IMPL(sphincs_shake_128f, PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN)
SIGN_IMPL(sphincs_shake_128s, PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN)
SIGN_IMPL(sphincs_shake_192f, PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN)
SIGN_IMPL(sphincs_shake_192s, PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN)
SIGN_IMPL(sphincs_shake_256f, PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN)
SIGN_IMPL(sphincs_shake_256s, PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN)

#undef SIGN_IMPL

#endif /* NEXTSSL_BUILD_LITE */
