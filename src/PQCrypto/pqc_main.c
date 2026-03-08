#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

/*
 * pqc_main.c — PQC algorithm wrappers
 *
 * Migrated from src/utils/pqc_main.c.
 * Changes from original:
 *   1. All "PQCrypto/..." include prefixes simplified to subsystem-relative paths.
 *   2. pqc_randombytes_seed() in derand wrappers is now preceded by
 *      pqc_seed_from_coins() which applies HKDF domain-separation via rootkey_get
 *      so that the same coin bytes for different algorithms yield distinct seeds.
 *   3. New dependency: common/udbf/rootkey.h
 */

/* Include Algorithm APIs */
#ifdef ENABLE_ML_KEM
#include "crypto_kem/ml-kem-768/clean/api.h"
#include "crypto_kem/ml-kem-1024/clean/api.h"
#include "crypto_kem/ml-kem-512/clean/api.h"
#endif

#ifdef ENABLE_ML_DSA
#include "crypto_sign/ml-dsa-44/clean/api.h"
#include "crypto_sign/ml-dsa-65/clean/api.h"
#include "crypto_sign/ml-dsa-87/clean/api.h"
#endif

#ifdef ENABLE_HQC
#include "crypto_kem/hqc-128/clean/api.h"
#include "crypto_kem/hqc-192/clean/api.h"
#include "crypto_kem/hqc-256/clean/api.h"
#endif

#ifdef ENABLE_FALCON
#include "crypto_sign/falcon-512/clean/api.h"
#include "crypto_sign/falcon-1024/clean/api.h"
#include "crypto_sign/falcon-padded-512/clean/api.h"
#include "crypto_sign/falcon-padded-1024/clean/api.h"
#endif

#ifdef ENABLE_MCELIECE
#include "crypto_kem/mceliece348864/clean/api.h"
#include "crypto_kem/mceliece348864f/clean/api.h"
#include "crypto_kem/mceliece460896/clean/api.h"
#include "crypto_kem/mceliece460896f/clean/api.h"
#include "crypto_kem/mceliece6688128/clean/api.h"
#include "crypto_kem/mceliece6688128f/clean/api.h"
#include "crypto_kem/mceliece6960119/clean/api.h"
#include "crypto_kem/mceliece6960119f/clean/api.h"
#include "crypto_kem/mceliece8192128/clean/api.h"
#include "crypto_kem/mceliece8192128f/clean/api.h"
#endif

#ifdef ENABLE_SPHINCS
#include "crypto_sign/sphincs-sha2-128f-simple/clean/api.h"
#include "crypto_sign/sphincs-sha2-128s-simple/clean/api.h"
#include "crypto_sign/sphincs-sha2-192f-simple/clean/api.h"
#include "crypto_sign/sphincs-sha2-192s-simple/clean/api.h"
#include "crypto_sign/sphincs-sha2-256f-simple/clean/api.h"
#include "crypto_sign/sphincs-sha2-256s-simple/clean/api.h"
#include "crypto_sign/sphincs-shake-128f-simple/clean/api.h"
#include "crypto_sign/sphincs-shake-128s-simple/clean/api.h"
#include "crypto_sign/sphincs-shake-192f-simple/clean/api.h"
#include "crypto_sign/sphincs-shake-192s-simple/clean/api.h"
#include "crypto_sign/sphincs-shake-256f-simple/clean/api.h"
#include "crypto_sign/sphincs-shake-256s-simple/clean/api.h"
#endif

/* Core APIs */
#include "common/hkdf/hkdf.h"
#include "common/randombytes.h"

/* Root-key orchestrator (domain-separated seed derivation) */
#include "../seed/udbf/rootkey.h"

/* Forward-declare the seed functions from randombytes.c */
EXPORT void pqc_randombytes_seed(const uint8_t *seed, size_t seed_len);
EXPORT void pqc_randombytes_reseed(const uint8_t *seed, size_t seed_len);
EXPORT void pqc_set_udbf(const uint8_t *buf, size_t len);

EXPORT int pqc_set_mode(int unsafe) {
    (void)unsafe;
    return 0;
}

/*
 * Internal helper: derive a domain-separated 32-byte DRBG seed from
 * the caller-provided coin bytes @coins and the algorithm @label, then
 * seed the global DRBG.  This ensures that identical coin bytes fed to
 * different algorithms (or different operations of the same algorithm)
 * produce independent DRBG streams.
 */
static void pqc_seed_from_coins(const char *label,
                                 const uint8_t *coins, size_t coins_len)
{
    uint8_t seed[32];
    rootkey_get(ROOTKEY_MODE_SEED, label, coins, coins_len, seed, 32);
    pqc_randombytes_seed(seed, 32);
    /* Wipe seed buffer after use */
    volatile uint8_t *p = (volatile uint8_t *)seed;
    for (int i = 0; i < 32; i++) p[i] = 0;
}

/* Set User Determined Byte Feeder (UDBF) */
EXPORT void pqc_udbf_feed(const uint8_t *buf, size_t len) {
    pqc_set_udbf(buf, len);
}

/* Initialize DRBG with HKDF-derived seed */
EXPORT int pqc_drbg_seed(const uint8_t *seed, size_t seed_len,
                          const uint8_t *salt, size_t salt_len,
                          const uint8_t *info, size_t info_len) {
    uint8_t prk[32];
    uint8_t okm[32];
    hkdf_extract(salt, salt_len, seed, seed_len, prk);
    hkdf_expand(prk, 32, info, info_len, okm, 32);
    pqc_randombytes_seed(okm, 32);
    return 0;
}

EXPORT int pqc_drbg_reseed(const uint8_t *seed, size_t seed_len,
                             const uint8_t *salt, size_t salt_len) {
    uint8_t prk[32];
    uint8_t okm[32];
    hkdf_extract(salt, salt_len, seed, seed_len, prk);
    hkdf_expand(prk, 32, NULL, 0, okm, 32);
    pqc_randombytes_reseed(okm, 32);
    return 0;
}

EXPORT int pqc_randombytes(uint8_t *out, size_t out_len) {
    return randombytes(out, out_len);
}

/* ========================================================================== */
/*  ML-KEM (Kyber)                                                             */
/* ========================================================================== */
#ifdef ENABLE_ML_KEM

/* ML-KEM-512 */
EXPORT int pqc_mlkem512_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mlkem512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    pqc_seed_from_coins("mlkem512-keypair", coins, 32);
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mlkem512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mlkem512_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    pqc_seed_from_coins("mlkem512-encaps", coins, 32);
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mlkem512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* ML-KEM-768 */
EXPORT int pqc_mlkem768_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mlkem768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    pqc_seed_from_coins("mlkem768-keypair", coins, 32);
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    pqc_seed_from_coins("mlkem768-encaps", coins, 32);
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* ML-KEM-1024 */
EXPORT int pqc_mlkem1024_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mlkem1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    pqc_seed_from_coins("mlkem1024-keypair", coins, 32);
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mlkem1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mlkem1024_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    pqc_seed_from_coins("mlkem1024-encaps", coins, 32);
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mlkem1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk);
}
#endif /* ENABLE_ML_KEM */

/* ========================================================================== */
/*  ML-DSA (Dilithium)                                                         */
/* ========================================================================== */
#ifdef ENABLE_ML_DSA

/* ML-DSA-44 */
EXPORT int pqc_mldsa44_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_mldsa44_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("mldsa44-keypair", seed, 32);
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_mldsa44_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_mldsa44_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) {
    (void)ctx; (void)ctxlen;
    pqc_seed_from_coins("mldsa44-sign", rnd, 32);
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_mldsa44_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* ML-DSA-65 */
EXPORT int pqc_mldsa65_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_mldsa65_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("mldsa65-keypair", seed, 32);
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_mldsa65_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_mldsa65_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) {
    (void)ctx; (void)ctxlen;
    pqc_seed_from_coins("mldsa65-sign", rnd, 32);
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_mldsa65_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* ML-DSA-87 */
EXPORT int pqc_mldsa87_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_mldsa87_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("mldsa87-keypair", seed, 32);
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_mldsa87_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_mldsa87_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) {
    (void)ctx; (void)ctxlen;
    pqc_seed_from_coins("mldsa87-sign", rnd, 32);
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_mldsa87_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
#endif /* ENABLE_ML_DSA */

/* ========================================================================== */
/*  Falcon                                                                     */
/* ========================================================================== */
#ifdef ENABLE_FALCON

/* Falcon-512 */
EXPORT int pqc_falcon512_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falcon512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("falcon512-keypair", seed, 32);
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falcon512_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falcon512_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("falcon512-sign", rnd, 32);
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falcon512_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* Falcon-1024 */
EXPORT int pqc_falcon1024_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falcon1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("falcon1024-keypair", seed, 32);
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falcon1024_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falcon1024_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("falcon1024-sign", rnd, 32);
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falcon1024_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* Falcon-Padded-512 */
EXPORT int pqc_falconpadded512_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falconpadded512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("falcon-padded512-keypair", seed, 32);
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falconpadded512_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falconpadded512_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("falcon-padded512-sign", rnd, 32);
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falconpadded512_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* Falcon-Padded-1024 */
EXPORT int pqc_falconpadded1024_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falconpadded1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("falcon-padded1024-keypair", seed, 32);
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_falconpadded1024_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falconpadded1024_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("falcon-padded1024-sign", rnd, 32);
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}
EXPORT int pqc_falconpadded1024_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
#endif /* ENABLE_FALCON */

/* ========================================================================== */
/*  HQC                                                                        */
/* ========================================================================== */
#ifdef ENABLE_HQC

/* HQC-128 */
EXPORT int pqc_hqc128_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_hqc128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("hqc128-keypair", entropy, 32);
    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_hqc128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_hqc128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("hqc128-encaps", entropy, 32);
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_hqc128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* HQC-192 */
EXPORT int pqc_hqc192_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_hqc192_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("hqc192-keypair", entropy, 32);
    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_hqc192_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_hqc192_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("hqc192-encaps", entropy, 32);
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_hqc192_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* HQC-256 */
EXPORT int pqc_hqc256_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_hqc256_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("hqc256-keypair", entropy, 32);
    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_hqc256_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_hqc256_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("hqc256-encaps", entropy, 32);
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_hqc256_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss, ct, sk);
}
#endif /* ENABLE_HQC */

/* ========================================================================== */
/*  Classic McEliece                                                           */
/* ========================================================================== */
#ifdef ENABLE_MCELIECE

/* mceliece348864 */
EXPORT int pqc_mceliece348864_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece348864_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece348864-keypair", entropy, 32);
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece348864_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece348864_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece348864-encaps", entropy, 32);
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece348864_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece348864f */
EXPORT int pqc_mceliece348864f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece348864f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece348864f-keypair", entropy, 32);
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece348864f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece348864f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece348864f-encaps", entropy, 32);
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece348864f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece460896 */
EXPORT int pqc_mceliece460896_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece460896_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece460896-keypair", entropy, 32);
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece460896_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece460896_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece460896-encaps", entropy, 32);
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece460896_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece460896f */
EXPORT int pqc_mceliece460896f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece460896f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece460896f-keypair", entropy, 32);
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece460896f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece460896f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece460896f-encaps", entropy, 32);
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece460896f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece6688128 */
EXPORT int pqc_mceliece6688128_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6688128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6688128-keypair", entropy, 32);
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6688128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6688128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6688128-encaps", entropy, 32);
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6688128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece6688128f */
EXPORT int pqc_mceliece6688128f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6688128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6688128f-keypair", entropy, 32);
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6688128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6688128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6688128f-encaps", entropy, 32);
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6688128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece6960119 */
EXPORT int pqc_mceliece6960119_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6960119_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6960119-keypair", entropy, 32);
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6960119_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6960119_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6960119-encaps", entropy, 32);
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6960119_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece6960119f */
EXPORT int pqc_mceliece6960119f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6960119f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6960119f-keypair", entropy, 32);
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece6960119f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6960119f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece6960119f-encaps", entropy, 32);
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece6960119f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece8192128 */
EXPORT int pqc_mceliece8192128_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece8192128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece8192128-keypair", entropy, 32);
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece8192128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece8192128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece8192128-encaps", entropy, 32);
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece8192128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* mceliece8192128f */
EXPORT int pqc_mceliece8192128f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece8192128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece8192128f-keypair", entropy, 32);
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pk, sk);
}
EXPORT int pqc_mceliece8192128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece8192128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_seed_from_coins("mceliece8192128f-encaps", entropy, 32);
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}
EXPORT int pqc_mceliece8192128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(ss, ct, sk);
}
#endif /* ENABLE_MCELIECE */

/* ========================================================================== */
/*  SPHINCS+                                                                   */
/* ========================================================================== */
#ifdef ENABLE_SPHINCS

/* SHA2 variants */
EXPORT int pqc_sphincssha2128fsimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincssha2128fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-sha2-128f-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincssha2128fsimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincssha2128fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-sha2-128f-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincssha2128fsimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincssha2128ssimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincssha2128ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-sha2-128s-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincssha2128ssimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincssha2128ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-sha2-128s-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincssha2128ssimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincssha2192fsimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincssha2192fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-sha2-192f-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincssha2192fsimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincssha2192fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-sha2-192f-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincssha2192fsimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincssha2192ssimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincssha2192ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-sha2-192s-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincssha2192ssimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincssha2192ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-sha2-192s-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincssha2192ssimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincssha2256fsimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincssha2256fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-sha2-256f-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincssha2256fsimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincssha2256fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-sha2-256f-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincssha2256fsimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincssha2256ssimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincssha2256ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-sha2-256s-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincssha2256ssimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincssha2256ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-sha2-256s-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincssha2256ssimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

/* SHAKE variants */
EXPORT int pqc_sphincsshake128fsimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincsshake128fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-shake-128f-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincsshake128fsimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincsshake128fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-shake-128f-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincsshake128fsimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincsshake128ssimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincsshake128ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-shake-128s-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincsshake128ssimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincsshake128ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-shake-128s-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincsshake128ssimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincsshake192fsimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincsshake192fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-shake-192f-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincsshake192fsimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincsshake192fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-shake-192f-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincsshake192fsimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincsshake192ssimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincsshake192ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-shake-192s-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincsshake192ssimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincsshake192ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-shake-192s-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincsshake192ssimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincsshake256fsimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincsshake256fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-shake-256f-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincsshake256fsimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincsshake256fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-shake-256f-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincsshake256fsimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

EXPORT int pqc_sphincsshake256ssimple_keypair(uint8_t *pk, uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk); }
EXPORT int pqc_sphincsshake256ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_seed_from_coins("sphincs-shake-256s-keypair", seed, 32);
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}
EXPORT int pqc_sphincsshake256ssimple_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk); }
EXPORT int pqc_sphincsshake256ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) {
    pqc_seed_from_coins("sphincs-shake-256s-sign", rnd, 32);
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, sl, m, ml, sk);
}
EXPORT int pqc_sphincsshake256ssimple_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(sig, sl, m, ml, pk); }

#endif /* ENABLE_SPHINCS */
