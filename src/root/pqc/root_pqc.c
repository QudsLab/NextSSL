/* root_pqc.c — Post-Quantum Cryptography API Implementation (Plan 405)
 *
 * Thin NEXTSSL_API wrappers over pqc_main.c internal pqc_* functions.
 * Forward-declares all pqc_* symbols as extern; no second include of PQC headers.
 */
#include "root_pqc.h"
#include <stddef.h>
#include <stdint.h>

/* =========================================================================
 * Forward declarations — all pqc_* functions from pqc_main.c
 * =========================================================================*/

/* DRBG / RNG */
extern void pqc_randombytes_seed    (const uint8_t *seed, size_t seed_len);
extern void pqc_randombytes_reseed  (const uint8_t *seed, size_t seed_len);
extern int  pqc_randombytes         (uint8_t *out, size_t out_len);
extern int  pqc_drbg_seed           (const uint8_t *seed, size_t seed_len, const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len);
extern int  pqc_drbg_reseed         (const uint8_t *seed, size_t seed_len, const uint8_t *salt, size_t salt_len);
extern void pqc_udbf_feed           (const uint8_t *buf, size_t len);
extern void pqc_set_udbf            (const uint8_t *buf, size_t len);
extern int  pqc_set_mode             (int unsafe);

#ifdef ENABLE_ML_KEM
extern int pqc_mlkem512_keypair          (uint8_t *pk, uint8_t *sk);
extern int pqc_mlkem512_keypair_derand   (uint8_t *pk, uint8_t *sk, const uint8_t *coins);
extern int pqc_mlkem512_encaps           (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mlkem512_encaps_derand    (uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
extern int pqc_mlkem512_decaps           (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mlkem768_keypair          (uint8_t *pk, uint8_t *sk);
extern int pqc_mlkem768_keypair_derand   (uint8_t *pk, uint8_t *sk, const uint8_t *coins);
extern int pqc_mlkem768_encaps           (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mlkem768_encaps_derand    (uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
extern int pqc_mlkem768_decaps           (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mlkem1024_keypair         (uint8_t *pk, uint8_t *sk);
extern int pqc_mlkem1024_keypair_derand  (uint8_t *pk, uint8_t *sk, const uint8_t *coins);
extern int pqc_mlkem1024_encaps          (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mlkem1024_encaps_derand   (uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
extern int pqc_mlkem1024_decaps          (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

#ifdef ENABLE_ML_DSA
extern int pqc_mldsa44_keypair         (uint8_t *pk, uint8_t *sk);
extern int pqc_mldsa44_keypair_derand  (uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_mldsa44_sign            (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_mldsa44_sign_derand     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_mldsa44_verify          (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_mldsa65_keypair         (uint8_t *pk, uint8_t *sk);
extern int pqc_mldsa65_keypair_derand  (uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_mldsa65_sign            (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_mldsa65_sign_derand     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_mldsa65_verify          (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_mldsa87_keypair         (uint8_t *pk, uint8_t *sk);
extern int pqc_mldsa87_keypair_derand  (uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_mldsa87_sign            (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_mldsa87_sign_derand     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_mldsa87_verify          (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
#endif

#ifdef ENABLE_FALCON
extern int pqc_falcon512_keypair           (uint8_t *pk, uint8_t *sk);
extern int pqc_falcon512_keypair_derand    (uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_falcon512_sign              (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_falcon512_sign_derand       (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_falcon512_verify            (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_falcon1024_keypair          (uint8_t *pk, uint8_t *sk);
extern int pqc_falcon1024_keypair_derand   (uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_falcon1024_sign             (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_falcon1024_sign_derand      (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_falcon1024_verify           (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_falconpadded512_keypair     (uint8_t *pk, uint8_t *sk);
extern int pqc_falconpadded512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_falconpadded512_sign        (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_falconpadded512_sign_derand (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_falconpadded512_verify      (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_falconpadded1024_keypair    (uint8_t *pk, uint8_t *sk);
extern int pqc_falconpadded1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_falconpadded1024_sign       (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_falconpadded1024_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_falconpadded1024_verify     (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
#endif

#ifdef ENABLE_HQC
extern int pqc_hqc128_keypair          (uint8_t *pk, uint8_t *sk);
extern int pqc_hqc128_keypair_derand   (uint8_t *pk, uint8_t *sk, const uint8_t *e);
extern int pqc_hqc128_encaps           (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_hqc128_encaps_derand    (uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *e);
extern int pqc_hqc128_decaps           (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_hqc192_keypair          (uint8_t *pk, uint8_t *sk);
extern int pqc_hqc192_keypair_derand   (uint8_t *pk, uint8_t *sk, const uint8_t *e);
extern int pqc_hqc192_encaps           (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_hqc192_encaps_derand    (uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *e);
extern int pqc_hqc192_decaps           (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_hqc256_keypair          (uint8_t *pk, uint8_t *sk);
extern int pqc_hqc256_keypair_derand   (uint8_t *pk, uint8_t *sk, const uint8_t *e);
extern int pqc_hqc256_encaps           (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_hqc256_encaps_derand    (uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *e);
extern int pqc_hqc256_decaps           (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

#ifdef ENABLE_MCELIECE
extern int pqc_mceliece348864_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece348864_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece348864_encaps   (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece348864_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece348864_decaps   (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece348864f_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece348864f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece348864f_encaps  (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece348864f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece348864f_decaps  (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece460896_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece460896_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece460896_encaps   (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece460896_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece460896_decaps   (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece460896f_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece460896f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece460896f_encaps  (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece460896f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece460896f_decaps  (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece6688128_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece6688128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece6688128_encaps  (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece6688128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece6688128_decaps  (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece6688128f_keypair(uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece6688128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece6688128f_encaps (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece6688128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece6688128f_decaps (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece6960119_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece6960119_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece6960119_encaps  (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece6960119_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece6960119_decaps  (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece6960119f_keypair(uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece6960119f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece6960119f_encaps (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece6960119f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece6960119f_decaps (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece8192128_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece8192128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece8192128_encaps  (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece8192128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece8192128_decaps  (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
extern int pqc_mceliece8192128f_keypair(uint8_t *pk, uint8_t *sk);
extern int pqc_mceliece8192128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy);
extern int pqc_mceliece8192128f_encaps (uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int pqc_mceliece8192128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy);
extern int pqc_mceliece8192128f_decaps (uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

#ifdef ENABLE_SPHINCS
/* pqc_main.c uses compressed names: sphincssha2128fsimple etc. */
extern int pqc_sphincssha2128fsimple_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincssha2128fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincssha2128fsimple_sign     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincssha2128fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincssha2128fsimple_verify   (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincssha2128ssimple_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincssha2128ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincssha2128ssimple_sign     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincssha2128ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincssha2128ssimple_verify   (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincssha2192fsimple_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincssha2192fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincssha2192fsimple_sign     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincssha2192fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincssha2192fsimple_verify   (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincssha2192ssimple_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincssha2192ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincssha2192ssimple_sign     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincssha2192ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincssha2192ssimple_verify   (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincssha2256fsimple_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincssha2256fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincssha2256fsimple_sign     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincssha2256fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincssha2256fsimple_verify   (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincssha2256ssimple_keypair  (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincssha2256ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincssha2256ssimple_sign     (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincssha2256ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincssha2256ssimple_verify   (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincsshake128fsimple_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincsshake128fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincsshake128fsimple_sign    (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincsshake128fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincsshake128fsimple_verify  (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincsshake128ssimple_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincsshake128ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincsshake128ssimple_sign    (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincsshake128ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincsshake128ssimple_verify  (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincsshake192fsimple_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincsshake192fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincsshake192fsimple_sign    (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincsshake192fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincsshake192fsimple_verify  (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincsshake192ssimple_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincsshake192ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincsshake192ssimple_sign    (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincsshake192ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincsshake192ssimple_verify  (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincsshake256fsimple_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincsshake256fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincsshake256fsimple_sign    (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincsshake256fsimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincsshake256fsimple_verify  (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
extern int pqc_sphincsshake256ssimple_keypair (uint8_t *pk, uint8_t *sk);
extern int pqc_sphincsshake256ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int pqc_sphincsshake256ssimple_sign    (uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk);
extern int pqc_sphincsshake256ssimple_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd);
extern int pqc_sphincsshake256ssimple_verify  (const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk);
#endif

/* =========================================================================
 * DRBG / RNG wrappers
 * =========================================================================*/
void nextssl_pqc_randombytes_seed(const uint8_t *seed, size_t seed_len)    { pqc_randombytes_seed(seed, seed_len); }
void nextssl_pqc_randombytes_reseed(const uint8_t *seed, size_t seed_len)  { pqc_randombytes_reseed(seed, seed_len); }
int  nextssl_pqc_randombytes(uint8_t *out, size_t out_len)                 { return pqc_randombytes(out, out_len); }
int  nextssl_pqc_drbg_seed(const uint8_t *seed, size_t seed_len, const uint8_t *salt, size_t salt_len, const uint8_t *info, size_t info_len) { return pqc_drbg_seed(seed, seed_len, salt, salt_len, info, info_len); }
int  nextssl_pqc_drbg_reseed(const uint8_t *seed, size_t seed_len, const uint8_t *salt, size_t salt_len) { return pqc_drbg_reseed(seed, seed_len, salt, salt_len); }
void nextssl_pqc_udbf_feed(const uint8_t *buf, size_t len)                 { pqc_udbf_feed(buf, len); }
void nextssl_pqc_set_udbf(const uint8_t *buf, size_t len)                { pqc_set_udbf(buf, len); }
int  nextssl_pqc_set_mode(int unsafe)                                    { return pqc_set_mode(unsafe); }

/* =========================================================================
 * ML-KEM wrappers
 * =========================================================================*/
#ifdef ENABLE_ML_KEM
int nextssl_pqc_mlkem512_keypair(uint8_t *pk, uint8_t *sk)                                                   { return pqc_mlkem512_keypair(pk, sk); }
int nextssl_pqc_mlkem512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins)                      { return pqc_mlkem512_keypair_derand(pk, sk, coins); }
int nextssl_pqc_mlkem512_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)                                 { return pqc_mlkem512_encaps(ct, ss, pk); }
int nextssl_pqc_mlkem512_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins)    { return pqc_mlkem512_encaps_derand(ct, ss, pk, coins); }
int nextssl_pqc_mlkem512_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)                           { return pqc_mlkem512_decaps(ss, ct, sk); }
int nextssl_pqc_mlkem768_keypair(uint8_t *pk, uint8_t *sk)                                                   { return pqc_mlkem768_keypair(pk, sk); }
int nextssl_pqc_mlkem768_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins)                      { return pqc_mlkem768_keypair_derand(pk, sk, coins); }
int nextssl_pqc_mlkem768_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)                                 { return pqc_mlkem768_encaps(ct, ss, pk); }
int nextssl_pqc_mlkem768_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins)    { return pqc_mlkem768_encaps_derand(ct, ss, pk, coins); }
int nextssl_pqc_mlkem768_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)                           { return pqc_mlkem768_decaps(ss, ct, sk); }
int nextssl_pqc_mlkem1024_keypair(uint8_t *pk, uint8_t *sk)                                                  { return pqc_mlkem1024_keypair(pk, sk); }
int nextssl_pqc_mlkem1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *coins)                     { return pqc_mlkem1024_keypair_derand(pk, sk, coins); }
int nextssl_pqc_mlkem1024_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)                                { return pqc_mlkem1024_encaps(ct, ss, pk); }
int nextssl_pqc_mlkem1024_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins)   { return pqc_mlkem1024_encaps_derand(ct, ss, pk, coins); }
int nextssl_pqc_mlkem1024_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)                          { return pqc_mlkem1024_decaps(ss, ct, sk); }
#endif

/* =========================================================================
 * ML-DSA wrappers
 * =========================================================================*/
#ifdef ENABLE_ML_DSA
int nextssl_pqc_mldsa44_keypair(uint8_t *pk, uint8_t *sk)                                                                                      { return pqc_mldsa44_keypair(pk, sk); }
int nextssl_pqc_mldsa44_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)                                                          { return pqc_mldsa44_keypair_derand(pk, sk, seed); }
int nextssl_pqc_mldsa44_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)                                         { return pqc_mldsa44_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_mldsa44_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) { return pqc_mldsa44_sign_derand(sig, sl, m, ml, ctx, ctxlen, sk, rnd); }
int nextssl_pqc_mldsa44_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk)                                  { return pqc_mldsa44_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_mldsa65_keypair(uint8_t *pk, uint8_t *sk)                                                                                      { return pqc_mldsa65_keypair(pk, sk); }
int nextssl_pqc_mldsa65_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)                                                          { return pqc_mldsa65_keypair_derand(pk, sk, seed); }
int nextssl_pqc_mldsa65_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)                                         { return pqc_mldsa65_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_mldsa65_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) { return pqc_mldsa65_sign_derand(sig, sl, m, ml, ctx, ctxlen, sk, rnd); }
int nextssl_pqc_mldsa65_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk)                                  { return pqc_mldsa65_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_mldsa87_keypair(uint8_t *pk, uint8_t *sk)                                                                                      { return pqc_mldsa87_keypair(pk, sk); }
int nextssl_pqc_mldsa87_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)                                                          { return pqc_mldsa87_keypair_derand(pk, sk, seed); }
int nextssl_pqc_mldsa87_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)                                         { return pqc_mldsa87_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_mldsa87_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *ctx, size_t ctxlen, const uint8_t *sk, const uint8_t *rnd) { return pqc_mldsa87_sign_derand(sig, sl, m, ml, ctx, ctxlen, sk, rnd); }
int nextssl_pqc_mldsa87_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk)                                  { return pqc_mldsa87_verify(sig, sl, m, ml, pk); }
#endif

/* =========================================================================
 * Falcon wrappers
 * =========================================================================*/
#ifdef ENABLE_FALCON
int nextssl_pqc_falcon512_keypair(uint8_t *pk, uint8_t *sk)                                                             { return pqc_falcon512_keypair(pk, sk); }
int nextssl_pqc_falcon512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)                                 { return pqc_falcon512_keypair_derand(pk, sk, seed); }
int nextssl_pqc_falcon512_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)                { return pqc_falcon512_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_falcon512_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_falcon512_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_falcon512_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk)         { return pqc_falcon512_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_falcon1024_keypair(uint8_t *pk, uint8_t *sk)                                                            { return pqc_falcon1024_keypair(pk, sk); }
int nextssl_pqc_falcon1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)                                { return pqc_falcon1024_keypair_derand(pk, sk, seed); }
int nextssl_pqc_falcon1024_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)               { return pqc_falcon1024_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_falcon1024_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_falcon1024_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_falcon1024_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk)        { return pqc_falcon1024_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_falconpadded512_keypair(uint8_t *pk, uint8_t *sk)                                                       { return pqc_falconpadded512_keypair(pk, sk); }
int nextssl_pqc_falconpadded512_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)                           { return pqc_falconpadded512_keypair_derand(pk, sk, seed); }
int nextssl_pqc_falconpadded512_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)          { return pqc_falconpadded512_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_falconpadded512_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_falconpadded512_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_falconpadded512_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk)   { return pqc_falconpadded512_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_falconpadded1024_keypair(uint8_t *pk, uint8_t *sk)                                                      { return pqc_falconpadded1024_keypair(pk, sk); }
int nextssl_pqc_falconpadded1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)                          { return pqc_falconpadded1024_keypair_derand(pk, sk, seed); }
int nextssl_pqc_falconpadded1024_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)         { return pqc_falconpadded1024_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_falconpadded1024_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_falconpadded1024_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_falconpadded1024_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk)  { return pqc_falconpadded1024_verify(sig, sl, m, ml, pk); }
#endif

/* =========================================================================
 * HQC wrappers
 * =========================================================================*/
#ifdef ENABLE_HQC
int nextssl_pqc_hqc128_keypair(uint8_t *pk, uint8_t *sk)                                                { return pqc_hqc128_keypair(pk, sk); }
int nextssl_pqc_hqc128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *e)                       { return pqc_hqc128_keypair_derand(pk, sk, e); }
int nextssl_pqc_hqc128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)                              { return pqc_hqc128_encaps(ct, ss, pk); }
int nextssl_pqc_hqc128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *e)     { return pqc_hqc128_encaps_derand(ct, ss, pk, e); }
int nextssl_pqc_hqc128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)                        { return pqc_hqc128_decaps(ss, ct, sk); }
int nextssl_pqc_hqc192_keypair(uint8_t *pk, uint8_t *sk)                                                { return pqc_hqc192_keypair(pk, sk); }
int nextssl_pqc_hqc192_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *e)                       { return pqc_hqc192_keypair_derand(pk, sk, e); }
int nextssl_pqc_hqc192_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)                              { return pqc_hqc192_encaps(ct, ss, pk); }
int nextssl_pqc_hqc192_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *e)     { return pqc_hqc192_encaps_derand(ct, ss, pk, e); }
int nextssl_pqc_hqc192_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)                        { return pqc_hqc192_decaps(ss, ct, sk); }
int nextssl_pqc_hqc256_keypair(uint8_t *pk, uint8_t *sk)                                                { return pqc_hqc256_keypair(pk, sk); }
int nextssl_pqc_hqc256_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *e)                       { return pqc_hqc256_keypair_derand(pk, sk, e); }
int nextssl_pqc_hqc256_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)                              { return pqc_hqc256_encaps(ct, ss, pk); }
int nextssl_pqc_hqc256_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *e)     { return pqc_hqc256_encaps_derand(ct, ss, pk, e); }
int nextssl_pqc_hqc256_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk)                        { return pqc_hqc256_decaps(ss, ct, sk); }
#endif

/* =========================================================================
 * McEliece wrappers
 * =========================================================================*/
#ifdef ENABLE_MCELIECE
int nextssl_pqc_mceliece348864_keypair(uint8_t *pk, uint8_t *sk)                        { return pqc_mceliece348864_keypair(pk, sk); }
int nextssl_pqc_mceliece348864_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece348864_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece348864_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)      { return pqc_mceliece348864_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece348864_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece348864_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece348864_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece348864_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece348864f_keypair(uint8_t *pk, uint8_t *sk)                       { return pqc_mceliece348864f_keypair(pk, sk); }
int nextssl_pqc_mceliece348864f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece348864f_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece348864f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)     { return pqc_mceliece348864f_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece348864f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece348864f_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece348864f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece348864f_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece460896_keypair(uint8_t *pk, uint8_t *sk)                        { return pqc_mceliece460896_keypair(pk, sk); }
int nextssl_pqc_mceliece460896_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece460896_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece460896_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)      { return pqc_mceliece460896_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece460896_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece460896_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece460896_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece460896_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece460896f_keypair(uint8_t *pk, uint8_t *sk)                       { return pqc_mceliece460896f_keypair(pk, sk); }
int nextssl_pqc_mceliece460896f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece460896f_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece460896f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)     { return pqc_mceliece460896f_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece460896f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece460896f_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece460896f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece460896f_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece6688128_keypair(uint8_t *pk, uint8_t *sk)                       { return pqc_mceliece6688128_keypair(pk, sk); }
int nextssl_pqc_mceliece6688128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece6688128_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece6688128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)     { return pqc_mceliece6688128_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece6688128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece6688128_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece6688128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece6688128_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece6688128f_keypair(uint8_t *pk, uint8_t *sk)                      { return pqc_mceliece6688128f_keypair(pk, sk); }
int nextssl_pqc_mceliece6688128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece6688128f_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece6688128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)    { return pqc_mceliece6688128f_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece6688128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece6688128f_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece6688128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece6688128f_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece6960119_keypair(uint8_t *pk, uint8_t *sk)                       { return pqc_mceliece6960119_keypair(pk, sk); }
int nextssl_pqc_mceliece6960119_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece6960119_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece6960119_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)     { return pqc_mceliece6960119_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece6960119_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece6960119_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece6960119_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece6960119_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece6960119f_keypair(uint8_t *pk, uint8_t *sk)                      { return pqc_mceliece6960119f_keypair(pk, sk); }
int nextssl_pqc_mceliece6960119f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece6960119f_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece6960119f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)    { return pqc_mceliece6960119f_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece6960119f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece6960119f_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece6960119f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece6960119f_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece8192128_keypair(uint8_t *pk, uint8_t *sk)                       { return pqc_mceliece8192128_keypair(pk, sk); }
int nextssl_pqc_mceliece8192128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece8192128_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece8192128_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)     { return pqc_mceliece8192128_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece8192128_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece8192128_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece8192128_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece8192128_decaps(ss, ct, sk); }
int nextssl_pqc_mceliece8192128f_keypair(uint8_t *pk, uint8_t *sk)                      { return pqc_mceliece8192128f_keypair(pk, sk); }
int nextssl_pqc_mceliece8192128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *entropy) { return pqc_mceliece8192128f_keypair_derand(pk, sk, entropy); }
int nextssl_pqc_mceliece8192128f_encaps(uint8_t *ct, uint8_t *ss, const uint8_t *pk)    { return pqc_mceliece8192128f_encaps(ct, ss, pk); }
int nextssl_pqc_mceliece8192128f_encaps_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *entropy) { return pqc_mceliece8192128f_encaps_derand(ct, ss, pk, entropy); }
int nextssl_pqc_mceliece8192128f_decaps(uint8_t *ss, const uint8_t *ct, const uint8_t *sk){ return pqc_mceliece8192128f_decaps(ss, ct, sk); }
#endif

/* =========================================================================
 * SPHINCS+ wrappers (map readable names → compressed pqc_ names)
 * =========================================================================*/
#ifdef ENABLE_SPHINCS
int nextssl_pqc_sphincs_sha2_128f_keypair(uint8_t *pk, uint8_t *sk)                                           { return pqc_sphincssha2128fsimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_sha2_128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)              { return pqc_sphincssha2128fsimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_sha2_128f_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)  { return pqc_sphincssha2128fsimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_sha2_128f_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincssha2128fsimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_sha2_128f_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincssha2128fsimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_sha2_128s_keypair(uint8_t *pk, uint8_t *sk)                                           { return pqc_sphincssha2128ssimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_sha2_128s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)              { return pqc_sphincssha2128ssimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_sha2_128s_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)  { return pqc_sphincssha2128ssimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_sha2_128s_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincssha2128ssimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_sha2_128s_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincssha2128ssimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_sha2_192f_keypair(uint8_t *pk, uint8_t *sk)                                           { return pqc_sphincssha2192fsimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_sha2_192f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)              { return pqc_sphincssha2192fsimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_sha2_192f_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)  { return pqc_sphincssha2192fsimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_sha2_192f_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincssha2192fsimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_sha2_192f_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincssha2192fsimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_sha2_192s_keypair(uint8_t *pk, uint8_t *sk)                                           { return pqc_sphincssha2192ssimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_sha2_192s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)              { return pqc_sphincssha2192ssimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_sha2_192s_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)  { return pqc_sphincssha2192ssimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_sha2_192s_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincssha2192ssimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_sha2_192s_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincssha2192ssimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_sha2_256f_keypair(uint8_t *pk, uint8_t *sk)                                           { return pqc_sphincssha2256fsimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_sha2_256f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)              { return pqc_sphincssha2256fsimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_sha2_256f_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)  { return pqc_sphincssha2256fsimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_sha2_256f_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincssha2256fsimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_sha2_256f_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincssha2256fsimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_sha2_256s_keypair(uint8_t *pk, uint8_t *sk)                                           { return pqc_sphincssha2256ssimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_sha2_256s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)              { return pqc_sphincssha2256ssimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_sha2_256s_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk)  { return pqc_sphincssha2256ssimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_sha2_256s_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincssha2256ssimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_sha2_256s_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincssha2256ssimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_shake_128f_keypair(uint8_t *pk, uint8_t *sk)                                          { return pqc_sphincsshake128fsimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_shake_128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)             { return pqc_sphincsshake128fsimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_shake_128f_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return pqc_sphincsshake128fsimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_shake_128f_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincsshake128fsimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_shake_128f_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincsshake128fsimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_shake_128s_keypair(uint8_t *pk, uint8_t *sk)                                          { return pqc_sphincsshake128ssimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_shake_128s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)             { return pqc_sphincsshake128ssimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_shake_128s_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return pqc_sphincsshake128ssimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_shake_128s_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincsshake128ssimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_shake_128s_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincsshake128ssimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_shake_192f_keypair(uint8_t *pk, uint8_t *sk)                                          { return pqc_sphincsshake192fsimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_shake_192f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)             { return pqc_sphincsshake192fsimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_shake_192f_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return pqc_sphincsshake192fsimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_shake_192f_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincsshake192fsimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_shake_192f_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincsshake192fsimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_shake_192s_keypair(uint8_t *pk, uint8_t *sk)                                          { return pqc_sphincsshake192ssimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_shake_192s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)             { return pqc_sphincsshake192ssimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_shake_192s_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return pqc_sphincsshake192ssimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_shake_192s_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincsshake192ssimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_shake_192s_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincsshake192ssimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_shake_256f_keypair(uint8_t *pk, uint8_t *sk)                                          { return pqc_sphincsshake256fsimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_shake_256f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)             { return pqc_sphincsshake256fsimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_shake_256f_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return pqc_sphincsshake256fsimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_shake_256f_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincsshake256fsimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_shake_256f_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincsshake256fsimple_verify(sig, sl, m, ml, pk); }
int nextssl_pqc_sphincs_shake_256s_keypair(uint8_t *pk, uint8_t *sk)                                          { return pqc_sphincsshake256ssimple_keypair(pk, sk); }
int nextssl_pqc_sphincs_shake_256s_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed)             { return pqc_sphincsshake256ssimple_keypair_derand(pk, sk, seed); }
int nextssl_pqc_sphincs_shake_256s_sign(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk) { return pqc_sphincsshake256ssimple_sign(sig, sl, m, ml, sk); }
int nextssl_pqc_sphincs_shake_256s_sign_derand(uint8_t *sig, size_t *sl, const uint8_t *m, size_t ml, const uint8_t *sk, const uint8_t *rnd) { return pqc_sphincsshake256ssimple_sign_derand(sig, sl, m, ml, sk, rnd); }
int nextssl_pqc_sphincs_shake_256s_verify(const uint8_t *sig, size_t sl, const uint8_t *m, size_t ml, const uint8_t *pk) { return pqc_sphincsshake256ssimple_verify(sig, sl, m, ml, pk); }
#endif
