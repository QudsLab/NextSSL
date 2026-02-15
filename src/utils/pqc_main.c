#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifdef _WIN32
    #define EXPORT __declspec(dllexport)
#else
    #define EXPORT __attribute__((visibility("default")))
#endif

/* Include Algorithm APIs */
#ifdef ENABLE_ML_KEM
#include "PQCrypto/crypto_kem/ml-kem-768/clean/api.h"
#include "PQCrypto/crypto_kem/ml-kem-1024/clean/api.h"
#include "PQCrypto/crypto_kem/ml-kem-512/clean/api.h"
#endif

#ifdef ENABLE_ML_DSA
#include "PQCrypto/crypto_sign/ml-dsa-44/clean/api.h"
#include "PQCrypto/crypto_sign/ml-dsa-65/clean/api.h"
#include "PQCrypto/crypto_sign/ml-dsa-87/clean/api.h"
#endif

#ifdef ENABLE_HQC
#include "PQCrypto/crypto_kem/hqc-128/clean/api.h"
#include "PQCrypto/crypto_kem/hqc-192/clean/api.h"
#include "PQCrypto/crypto_kem/hqc-256/clean/api.h"
#endif

#ifdef ENABLE_FALCON
#include "PQCrypto/crypto_sign/falcon-512/clean/api.h"
#include "PQCrypto/crypto_sign/falcon-1024/clean/api.h"
#include "PQCrypto/crypto_sign/falcon-padded-512/clean/api.h"
#include "PQCrypto/crypto_sign/falcon-padded-1024/clean/api.h"
#endif

#ifdef ENABLE_MCELIECE
#include "PQCrypto/crypto_kem/mceliece348864/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece348864f/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece460896/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece460896f/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece6688128/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece6688128f/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece6960119/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece6960119f/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece8192128/clean/api.h"
#include "PQCrypto/crypto_kem/mceliece8192128f/clean/api.h"
#endif

#ifdef ENABLE_SPHINCS
#include "PQCrypto/crypto_sign/sphincs-sha2-128f-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-sha2-128s-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-sha2-192f-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-sha2-192s-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-sha2-256f-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-sha2-256s-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-shake-128f-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-shake-128s-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-shake-192f-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-shake-192s-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-shake-256f-simple/clean/api.h"
#include "PQCrypto/crypto_sign/sphincs-shake-256s-simple/clean/api.h"
#endif

/* Include Core APIs */
#include "PQCrypto/common/hkdf/hkdf.h"
#include "PQCrypto/common/randombytes.h"

/* Helper functions from randombytes.c (not in header) */
EXPORT void pqc_randombytes_seed(const uint8_t *seed, size_t seed_len);
EXPORT void pqc_randombytes_reseed(const uint8_t *seed, size_t seed_len);
EXPORT void pqc_set_udbf(const uint8_t *buf, size_t len);

EXPORT int pqc_set_mode(int unsafe) {
    /* Placeholder for mode setting */
    return 0;
}

/* Set User Determined Byte Feeder (UDBF) */
/* If called with non-NULL buf, randombytes will return these bytes directly */
EXPORT void pqc_udbf_feed(const uint8_t *buf, size_t len) {
    pqc_set_udbf(buf, len);
}

/* Initialize DRBG with HKDF-derived seed */
EXPORT int pqc_drbg_seed(const uint8_t *seed, size_t seed_len, const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len) {
    uint8_t prk[32];
    uint8_t okm[32]; /* DRBG seed length */
    
    /* HKDF Extract */
    hkdf_extract(salt, salt_len, seed, seed_len, prk);
    
    /* HKDF Expand to get 32 bytes for DRBG seed */
    hkdf_expand(prk, 32, info, info_len, okm, 32);
    
    pqc_randombytes_seed(okm, 32);
    return 0;
}

EXPORT int pqc_drbg_reseed(const uint8_t *seed, size_t seed_len, const uint8_t *salt, size_t salt_len) {
    uint8_t prk[32];
    uint8_t okm[32];
    
    hkdf_extract(salt, salt_len, seed, seed_len, prk);
    hkdf_expand(prk, 32, NULL, 0, okm, 32);
    
    pqc_randombytes_reseed(okm, 32);
    return 0;
}

/* Helper to get bytes from global DRBG */
EXPORT int pqc_randombytes(uint8_t *out, size_t out_len) {
    return randombytes(out, out_len);
}

#ifdef ENABLE_ML_KEM
/* ML-KEM-512 Wrappers */
EXPORT int pqc_mlkem512_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mlkem512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    pqc_randombytes_seed(coins, 32);
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mlkem512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mlkem512_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    pqc_randombytes_seed(coins, 32);
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mlkem512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* ML-KEM-768 Wrappers */
EXPORT int pqc_mlkem768_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mlkem768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    /* Seed global DRBG with coins (Resets state for deterministic output) */
    pqc_randombytes_seed(coins, 32);
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    pqc_randombytes_seed(coins, 32);
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* ML-KEM-1024 Wrappers */
EXPORT int pqc_mlkem1024_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mlkem1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins) {
    pqc_randombytes_seed(coins, 32);
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mlkem1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mlkem1024_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins) {
    pqc_randombytes_seed(coins, 32);
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mlkem1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss, ct, sk);
}
#endif

#ifdef ENABLE_ML_DSA
/* ML-DSA-44 Wrappers */
EXPORT int pqc_mldsa44_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_mldsa44_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_mldsa44_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_mldsa44_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_mldsa44_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* ML-DSA-65 Wrappers */
EXPORT int pqc_mldsa65_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_mldsa65_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_mldsa65_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_mldsa65_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_mldsa65_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* ML-DSA-87 Wrappers */
EXPORT int pqc_mldsa87_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_mldsa87_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_mldsa87_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_mldsa87_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_mldsa87_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
#endif

#ifdef ENABLE_FALCON
/* Falcon-512 Wrappers */
EXPORT int pqc_falcon512_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falcon512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falcon512_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falcon512_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falcon512_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* Falcon-1024 Wrappers */
EXPORT int pqc_falcon1024_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falcon1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falcon1024_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falcon1024_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falcon1024_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCON1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* Falcon-Padded-512 Wrappers */
EXPORT int pqc_falconpadded512_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falconpadded512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falconpadded512_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falconpadded512_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falconpadded512_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCONPADDED512_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* Falcon-Padded-1024 Wrappers */
EXPORT int pqc_falconpadded1024_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falconpadded1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_falconpadded1024_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falconpadded1024_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_falconpadded1024_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_FALCONPADDED1024_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
#endif

#ifdef ENABLE_HQC
/* HQC-128 Wrappers */
EXPORT int pqc_hqc128_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_hqc128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_HQC128_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_hqc128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_hqc128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_HQC128_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_hqc128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_HQC128_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* HQC-192 Wrappers */
EXPORT int pqc_hqc192_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_hqc192_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_HQC192_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_hqc192_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_hqc192_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_HQC192_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_hqc192_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_HQC192_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* HQC-256 Wrappers */
EXPORT int pqc_hqc256_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_hqc256_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_HQC256_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_hqc256_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_hqc256_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_HQC256_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_hqc256_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_HQC256_CLEAN_crypto_kem_dec(ss, ct, sk);
}
#endif

#ifdef ENABLE_MCELIECE
/* Classic McEliece 348864 Wrappers */
EXPORT int pqc_mceliece348864_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece348864_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece348864_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece348864_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece348864_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE348864_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 348864f Wrappers */
EXPORT int pqc_mceliece348864f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece348864f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece348864f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece348864f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece348864f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE348864F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 460896 Wrappers */
EXPORT int pqc_mceliece460896_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece460896_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece460896_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece460896_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece460896_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE460896_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 460896f Wrappers */
EXPORT int pqc_mceliece460896f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece460896f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece460896f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece460896f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece460896f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE460896F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 6688128 Wrappers */
EXPORT int pqc_mceliece6688128_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6688128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6688128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6688128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6688128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 6688128f Wrappers */
EXPORT int pqc_mceliece6688128f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6688128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6688128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6688128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6688128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6688128F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 6960119 Wrappers */
EXPORT int pqc_mceliece6960119_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6960119_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6960119_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6960119_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6960119_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 6960119f Wrappers */
EXPORT int pqc_mceliece6960119f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6960119f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece6960119f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6960119f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece6960119f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE6960119F_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 8192128 Wrappers */
EXPORT int pqc_mceliece8192128_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece8192128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece8192128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece8192128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece8192128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128_CLEAN_crypto_kem_dec(ss, ct, sk);
}

/* Classic McEliece 8192128f Wrappers */
EXPORT int pqc_mceliece8192128f_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece8192128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_keypair(pk, sk);
}

EXPORT int pqc_mceliece8192128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece8192128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) {
    pqc_randombytes_seed(entropy, 32);
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_enc(ct, ss, pk);
}

EXPORT int pqc_mceliece8192128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return PQCLEAN_MCELIECE8192128F_CLEAN_crypto_kem_dec(ss, ct, sk);
}
#endif

#ifdef ENABLE_SPHINCS
/* SPHINCS+ SHA2-128f-simple Wrappers */
EXPORT int pqc_sphincssha2128fsimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2128fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2128fsimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2128fsimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2128fsimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHA2-128s-simple Wrappers */
EXPORT int pqc_sphincssha2128ssimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2128ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2128ssimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2128ssimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2128ssimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHA2-192f-simple Wrappers */
EXPORT int pqc_sphincssha2192fsimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2192fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2192fsimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2192fsimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2192fsimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHA2192FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHA2-192s-simple Wrappers */
EXPORT int pqc_sphincssha2192ssimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2192ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2192ssimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2192ssimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2192ssimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHA2192SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHA2-256f-simple Wrappers */
EXPORT int pqc_sphincssha2256fsimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2256fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2256fsimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2256fsimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2256fsimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHA2256FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHA2-256s-simple Wrappers */
EXPORT int pqc_sphincssha2256ssimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2256ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincssha2256ssimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2256ssimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincssha2256ssimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHA2256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHAKE-128f-simple Wrappers */
EXPORT int pqc_sphincsshake128fsimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake128fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake128fsimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake128fsimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake128fsimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHAKE128FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHAKE-128s-simple Wrappers */
EXPORT int pqc_sphincsshake128ssimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake128ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake128ssimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake128ssimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake128ssimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHAKE128SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHAKE-192f-simple Wrappers */
EXPORT int pqc_sphincsshake192fsimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake192fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake192fsimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake192fsimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake192fsimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHAKE192FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHAKE-192s-simple Wrappers */
EXPORT int pqc_sphincsshake192ssimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake192ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake192ssimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake192ssimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake192ssimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHAKE192SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHAKE-256f-simple Wrappers */
EXPORT int pqc_sphincsshake256fsimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake256fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake256fsimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake256fsimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake256fsimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHAKE256FSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}

/* SPHINCS+ SHAKE-256s-simple Wrappers */
EXPORT int pqc_sphincsshake256ssimple_keypair(uint8_t *pk, uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake256ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed) {
    pqc_randombytes_seed(seed, 32);
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_keypair(pk, sk);
}

EXPORT int pqc_sphincsshake256ssimple_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake256ssimple_sign_derand(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd) {
    pqc_randombytes_seed(rnd, 32);
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk);
}

EXPORT int pqc_sphincsshake256ssimple_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return PQCLEAN_SPHINCSSHAKE256SSIMPLE_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk);
}
#endif
