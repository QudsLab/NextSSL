/* root_pqc.h — Exported Post-Quantum Cryptography API (Plan 405)
 *
 * Unified header for all PQC algorithm families.
 * Thin wrappers over pqc_main.c; each nextssl_pqc_* function calls
 * the corresponding pqc_* function.
 *
 * Core PQC families are part of the unified public surface.
 */
#ifndef ROOT_PQC_H
#define ROOT_PQC_H

#include <stddef.h>
#include <stdint.h>
#include "../nextssl_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * DRBG / RNG control
 * -------------------------------------------------------------------------*/
NEXTSSL_API void nextssl_pqc_randombytes_seed(const uint8_t *seed, size_t seed_len);
NEXTSSL_API void nextssl_pqc_randombytes_reseed(const uint8_t *seed, size_t seed_len);
NEXTSSL_API int  nextssl_pqc_randombytes(uint8_t *out, size_t out_len);
NEXTSSL_API int  nextssl_pqc_drbg_seed(const uint8_t *seed, size_t seed_len,
                                        const uint8_t *salt, size_t salt_len,
                                        const uint8_t *info, size_t info_len);
NEXTSSL_API int  nextssl_pqc_drbg_reseed(const uint8_t *seed, size_t seed_len,
                                          const uint8_t *salt, size_t salt_len);
NEXTSSL_API void nextssl_pqc_udbf_feed(const uint8_t *buf, size_t len);
NEXTSSL_API void nextssl_pqc_set_udbf(const uint8_t *buf, size_t len);
NEXTSSL_API int  nextssl_pqc_set_mode(int unsafe);

/* =========================================================================
 * ML-KEM (Kyber)
 * =========================================================================*/
NEXTSSL_API int nextssl_pqc_mlkem512_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mlkem512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
NEXTSSL_API int nextssl_pqc_mlkem512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mlkem512_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
NEXTSSL_API int nextssl_pqc_mlkem512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mlkem768_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mlkem768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
NEXTSSL_API int nextssl_pqc_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
NEXTSSL_API int nextssl_pqc_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mlkem1024_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mlkem1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins);
NEXTSSL_API int nextssl_pqc_mlkem1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mlkem1024_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
NEXTSSL_API int nextssl_pqc_mlkem1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* =========================================================================
 * ML-DSA (Dilithium)
 * =========================================================================*/
NEXTSSL_API int nextssl_pqc_mldsa44_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mldsa44_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_mldsa44_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mldsa44_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_mldsa44_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_mldsa65_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mldsa65_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_mldsa65_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mldsa65_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_mldsa65_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_mldsa87_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mldsa87_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_mldsa87_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mldsa87_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_mldsa87_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

/* =========================================================================
 * Falcon
 * =========================================================================*/
NEXTSSL_API int nextssl_pqc_falcon512_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falcon512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_falcon512_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falcon512_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_falcon512_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_falcon1024_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falcon1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_falcon1024_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falcon1024_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_falcon1024_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_falconpadded512_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falconpadded512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_falconpadded512_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falconpadded512_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_falconpadded512_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_falconpadded1024_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falconpadded1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_falconpadded1024_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_falconpadded1024_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_falconpadded1024_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

/* =========================================================================
 * HQC
 * =========================================================================*/
NEXTSSL_API int nextssl_pqc_hqc128_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_hqc128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_hqc128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_hqc128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_hqc128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_hqc192_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_hqc192_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_hqc192_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_hqc192_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_hqc192_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_hqc256_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_hqc256_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_hqc256_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_hqc256_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_hqc256_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* =========================================================================
 * Classic McEliece (10 parameter sets)
 * =========================================================================*/
NEXTSSL_API int nextssl_pqc_mceliece348864_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece348864_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece348864_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece348864_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece348864_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece348864f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece348864f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece348864f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece348864f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece348864f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece460896_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece460896_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece460896_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece460896_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece460896_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece460896f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece460896f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece460896f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece460896f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece460896f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece6688128_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece6688128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6688128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece6688128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6688128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece6688128f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece6688128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6688128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece6688128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6688128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece6960119_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece6960119_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6960119_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece6960119_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6960119_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece6960119f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece6960119f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6960119f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece6960119f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece6960119f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece8192128_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece8192128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece8192128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece8192128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece8192128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

NEXTSSL_API int nextssl_pqc_mceliece8192128f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_mceliece8192128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece8192128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
NEXTSSL_API int nextssl_pqc_mceliece8192128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
NEXTSSL_API int nextssl_pqc_mceliece8192128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

/* =========================================================================
 * SPHINCS+ (SHA-2 and SHAKE families, all 12 parameter sets)
 * =========================================================================*/
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128f_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_sha2_128s_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128s_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_128s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_sha2_192f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192f_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_sha2_192s_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192s_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_192s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_sha2_256f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256f_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_sha2_256s_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256s_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_sha2_256s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_shake_128f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128f_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_shake_128s_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128s_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_shake_128s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_shake_192f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192f_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_shake_192s_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192s_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_shake_192s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_shake_256f_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256f_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256f_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256f_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

NEXTSSL_API int nextssl_pqc_sphincs_shake_256s_keypair(uint8_t *pk, uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256s_sign(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256s_sign_derand(uint8_t *sig, size_t *sig_len, const uint8_t *m, size_t mlen, const uint8_t *sk, const uint8_t *rnd);
NEXTSSL_API int nextssl_pqc_sphincs_shake_256s_verify(const uint8_t *sig, size_t sig_len, const uint8_t *m, size_t mlen, const uint8_t *pk);

#ifdef __cplusplus
}
#endif

#endif /* ROOT_PQC_H */
