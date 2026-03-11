/*
 * keygen.c — Key Generation Engine (Task 104)
 *
 * Implements all factory functions plus every per-algo and one-shot wrapper.
 *
 * Design invariant:
 *   - Coin bytes never leave this file as return values or output parameters.
 *   - Every stack buffer holding key material is memset(0) before return.
 *   - Factories condition all input through HKDF before initialising the DRBG,
 *     so the raw caller seed is never fed directly to a crypto primitive.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* Public API */
#include "keygen.h"

/* Private internals */
#include "internal/keygen_ctx.h"
#include "internal/keygen_fill.h"

/* Seed subsystems */
#include "hash/seed_hash.h"
#include "kdf/seed_kdf.h"
#include "password/seed_password.h"
#include "hd/seed_hd.h"
#include "rng/rng.h"
#include "udbf/udbf.h"
#include "drbg/drbg.h"

/* ECC primitives */
#include "../primitives/ecc/ed25519/ed25519.h"
#include "../primitives/ecc/curve448/curve448_det.h"
#include "../primitives/ecc/curve448/wolf_shim.h"          /* word32, byte  */
#include "../primitives/ecc/curve448/curve448.h"
#include "../primitives/ecc/curve448/ed448.h"
#include "../primitives/ecc/elligator2/elligator2.h"  /* elligator2_key_pair */

/* HKDF (factory conditioning) */
#include "../PQCrypto/common/hkdf/hkdf.h"

/* -----------------------------------------------------------------------
 * PQC _keypair_derand forward declarations.
 * These are defined in src/PQCrypto/pqc_main.c (EXPORT symbols).
 * --------------------------------------------------------------------- */
int pqc_mlkem512_keypair_derand    (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mlkem768_keypair_derand    (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mlkem1024_keypair_derand   (uint8_t *pk, uint8_t *sk, const uint8_t *s);

int pqc_mldsa44_keypair_derand     (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mldsa65_keypair_derand     (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mldsa87_keypair_derand     (uint8_t *pk, uint8_t *sk, const uint8_t *s);

int pqc_falcon512_keypair_derand       (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_falcon1024_keypair_derand      (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_falconpadded512_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_falconpadded1024_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);

int pqc_hqc128_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_hqc192_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_hqc256_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);

int pqc_mceliece348864_keypair_derand  (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece348864f_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece460896_keypair_derand  (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece460896f_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece6688128_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece6688128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece6960119_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece6960119f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece8192128_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_mceliece8192128f_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);

int pqc_sphincssha2128fsimple_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincssha2128ssimple_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincssha2192fsimple_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincssha2192ssimple_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincssha2256fsimple_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincssha2256ssimple_keypair_derand (uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincsshake128fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincsshake128ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincsshake192fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincsshake192ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincsshake256fsimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);
int pqc_sphincsshake256ssimple_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *s);

/* curve25519() for X25519 public-key derivation — in key_exchange.c */
void curve25519(unsigned char *shared_secret,
                const unsigned char *public_key,
                const unsigned char *private_key);

/* -----------------------------------------------------------------------
 * Internal helpers
 * --------------------------------------------------------------------- */

/* X25519 base point (Curve25519 Montgomery u=9) */
static const uint8_t x25519_base_u9[32] = { 9, 0 };

/*
 * alloc_ctx — calloc + set mode. Returns NULL on OOM.
 */
static keygen_ctx_t *alloc_ctx(keygen_mode_t mode)
{
    keygen_ctx_t *ctx = calloc(1, sizeof *ctx);
    if (ctx) ctx->mode = mode;
    return ctx;
}

/*
 * init_det_ctx — allocate a CTX_MODE_DET context whose DRBG is seeded
 * from the provided 32-byte PRK. Wipes prk before returning.
 */
static keygen_ctx_t *init_det_ctx(uint8_t prk[32])
{
    keygen_ctx_t *ctx = alloc_ctx(CTX_MODE_DET);
    if (ctx) drbg_init(&ctx->drbg, prk, 32);
    memset(prk, 0, 32);
    return ctx;
}

/* -----------------------------------------------------------------------
 * Context factories
 * --------------------------------------------------------------------- */

keygen_ctx_t *keygen_new_random(void)
{
    return alloc_ctx(CTX_MODE_RANDOM);
}

keygen_ctx_t *keygen_new_drbg(const uint8_t *seed, size_t seed_len,
                               const char    *label)
{
    if (!seed || seed_len == 0) return NULL;

    /* Condition through HKDF so the raw caller seed never hits the DRBG */
    size_t info_len = label ? strlen(label) : 0;
    uint8_t prk[32];
    int r = hkdf(NULL, 0,
                 seed, seed_len,
                 (const uint8_t *)label, info_len,
                 prk, 32);
    if (r != 0) return NULL;
    return init_det_ctx(prk);
}

keygen_ctx_t *keygen_new_hash(const uint8_t *seed, size_t seed_len,
                               const uint8_t *ctx_data, size_t ctx_len)
{
    if (!seed || seed_len == 0) return NULL;

    uint8_t prk[32];
    if (seed_hash_derive(seed, seed_len, ctx_data, ctx_len, prk, 32) != 0)
        return NULL;
    return init_det_ctx(prk);
}

keygen_ctx_t *keygen_new_kdf(const uint8_t *ikm,  size_t ikm_len,
                              const uint8_t *salt, size_t salt_len,
                              const uint8_t *info, size_t info_len)
{
    if (!ikm || ikm_len == 0) return NULL;

    uint8_t prk[32];
    if (seed_kdf_derive(ikm, ikm_len, salt, salt_len, info, info_len, prk, 32) != 0)
        return NULL;
    return init_det_ctx(prk);
}

keygen_ctx_t *keygen_new_password(const uint8_t *pwd,  size_t pwd_len,
                                   const uint8_t *salt, size_t salt_len,
                                   const keygen_argon2_params_t *params)
{
    if (!pwd || pwd_len == 0 || !salt || salt_len < 16) return NULL;

    uint8_t prk[32];
    if (seed_password_derive(pwd, pwd_len, salt, salt_len, params, prk, 32) != 0)
        return NULL;
    return init_det_ctx(prk);
}

keygen_ctx_t *keygen_new_udbf(const uint8_t *entropy, size_t ent_len,
                               const char    *label)
{
    (void)label; /* label is per-read, not per-feed */

    keygen_ctx_t *ctx = alloc_ctx(CTX_MODE_UDBF);
    if (!ctx) return NULL;

    if (udbf_ctx_feed(&ctx->udbf, entropy, ent_len) != UDBF_OK) {
        free(ctx);
        return NULL;
    }
    return ctx;
}

keygen_ctx_t *keygen_new_hd(const uint8_t *master_seed, size_t seed_len,
                             const char    *path)
{
    if (!master_seed || seed_len == 0 || !path) return NULL;

    uint8_t prk[32];
    if (seed_hd_derive(master_seed, seed_len, path, prk, 32) != 0)
        return NULL;
    return init_det_ctx(prk);
}

void keygen_free(keygen_ctx_t *ctx)
{
    if (!ctx) return;
    drbg_wipe(&ctx->drbg);       /* safe even if never initialised (just zeros) */
    udbf_ctx_wipe(&ctx->udbf);   /* safe even if never initialised (just zeros) */
    memset(ctx, 0, sizeof *ctx);
    free(ctx);
}

/* -----------------------------------------------------------------------
 * Raw fill (restricted export — not in primary/ public headers)
 * --------------------------------------------------------------------- */

int keygen_raw(keygen_ctx_t *ctx, const char *label,
               uint8_t *out, size_t out_len)
{
    return keygen_fill(ctx, label, out, out_len);
}

/* -----------------------------------------------------------------------
 * ECC wrappers
 * --------------------------------------------------------------------- */

int keygen_ed25519(keygen_ctx_t *ctx, uint8_t pk[32], uint8_t sk[64])
{
    uint8_t seed[32];
    int r = keygen_fill(ctx, "ed25519-keypair", seed, 32);
    if (r == 0)
        ed25519_create_keypair(pk, sk, seed);
    memset(seed, 0, sizeof seed);
    return r;
}

int keygen_x25519(keygen_ctx_t *ctx, uint8_t pk[32], uint8_t sk[32])
{
    uint8_t seed[32], ed_sk[64], ed_pk[32];
    int r = keygen_fill(ctx, "x25519-keypair", seed, 32);
    if (r == 0) {
        /*
         * ed25519_create_keypair: SHA-512(seed) → clamp → ed_sk[0..31] is
         * the Curve25519 scalar.  curve25519(pk, G=9, scalar) derives the
         * X25519 public key in Montgomery form.
         */
        ed25519_create_keypair(ed_pk, ed_sk, seed);
        memcpy(sk, ed_sk, 32);             /* X25519 sk = clamped scalar */
        curve25519(pk, x25519_base_u9, sk); /* X25519 pk = scalar × G    */
    }
    memset(seed, 0, sizeof seed);
    memset(ed_sk, 0, sizeof ed_sk);
    (void)ed_pk;
    return r;
}

int keygen_ed448(keygen_ctx_t *ctx, uint8_t pk[57], uint8_t sk[57])
{
    uint8_t coins[57];
    int r = keygen_fill(ctx, "ed448-keypair", coins, 57);
    if (r == 0) {
        ed448_key key;
        if (wc_ed448_init(&key) != 0) {
            r = -1;
        } else {
            word32 pkSz = 57, skSz = 57;
            /* import_private_key derives the public key from the private seed,
             * fixing the bug where import_private_only + make_public ignored
             * the provided coins and produced seed-independent output. */
            if (wc_ed448_import_private_key(coins, 57, NULL, 0, &key) != 0 ||
                wc_ed448_export_public(&key, pk, &pkSz) != 0               ||
                wc_ed448_export_private_only(&key, sk, &skSz) != 0) {
                r = -1;
            }
            wc_ed448_free(&key);
        }
    }
    memset(coins, 0, sizeof coins);
    return r;
}

int keygen_x448(keygen_ctx_t *ctx, uint8_t pk[56], uint8_t sk[56])
{
    uint8_t coins[32];
    int r = keygen_fill(ctx, "x448-keypair", coins, 32);
    if (r == 0) {
        curve448_key key;
        /* wc_curve448_make_key_deterministic calls wc_curve448_init internally */
        if (wc_curve448_make_key_deterministic(&key, coins, 32) != 0) {
            r = -1;
        } else {
            word32 pkSz = 56, skSz = 56;
            if (wc_curve448_export_public(&key, pk, &pkSz) != 0           ||
                wc_curve448_export_private_raw(&key, sk, &skSz) != 0) {
                r = -1;
            }
            wc_curve448_free(&key);
        }
    }
    memset(coins, 0, sizeof coins);
    return r;
}

int keygen_elligator2(keygen_ctx_t *ctx, uint8_t hidden[32], uint8_t sk[32])
{
    uint8_t seed[32];
    int r = keygen_fill(ctx, "elligator2-keypair", seed, 32);
    if (r == 0)
        elligator2_key_pair(hidden, sk, seed);
    memset(seed, 0, sizeof seed);
    return r;
}

/* -----------------------------------------------------------------------
 * PQC wrapper macro — all derand functions take 32-byte coins
 * KG_PQC(wrapper_fn_suffix, pqc_func_prefix, "domain-label")
 * --------------------------------------------------------------------- */
#define KG_PQC(name, pqcfn, lbl)                                               \
int keygen_##name(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk) {               \
    uint8_t coins[32];                                                         \
    int r = keygen_fill(ctx, lbl, coins, 32);                                  \
    if (r == 0) r = pqc_##pqcfn##_keypair_derand(pk, sk, coins);              \
    memset(coins, 0, sizeof coins);                                            \
    return r;                                                                  \
}

/* ---- ML-KEM ---- */
KG_PQC(ml_kem_512,  mlkem512,  "mlkem512-keypair" )
KG_PQC(ml_kem_768,  mlkem768,  "mlkem768-keypair" )
KG_PQC(ml_kem_1024, mlkem1024, "mlkem1024-keypair")

/* ---- ML-DSA ---- */
KG_PQC(ml_dsa_44, mldsa44, "mldsa44-keypair")
KG_PQC(ml_dsa_65, mldsa65, "mldsa65-keypair")
KG_PQC(ml_dsa_87, mldsa87, "mldsa87-keypair")

/* ---- Falcon ---- */
KG_PQC(falcon_512,          falcon512,           "falcon512-keypair"         )
KG_PQC(falcon_1024,         falcon1024,          "falcon1024-keypair"        )
KG_PQC(falcon_padded_512,   falconpadded512,     "falcon-padded512-keypair"  )
KG_PQC(falcon_padded_1024,  falconpadded1024,    "falcon-padded1024-keypair" )

/* ---- HQC ---- */
KG_PQC(hqc_128, hqc128, "hqc128-keypair")
KG_PQC(hqc_192, hqc192, "hqc192-keypair")
KG_PQC(hqc_256, hqc256, "hqc256-keypair")

/* ---- Classic McEliece ---- */
KG_PQC(mceliece_348864,   mceliece348864,   "mceliece348864-keypair"  )
KG_PQC(mceliece_348864f,  mceliece348864f,  "mceliece348864f-keypair" )
KG_PQC(mceliece_460896,   mceliece460896,   "mceliece460896-keypair"  )
KG_PQC(mceliece_460896f,  mceliece460896f,  "mceliece460896f-keypair" )
KG_PQC(mceliece_6688128,  mceliece6688128,  "mceliece6688128-keypair" )
KG_PQC(mceliece_6688128f, mceliece6688128f, "mceliece6688128f-keypair")
KG_PQC(mceliece_6960119,  mceliece6960119,  "mceliece6960119-keypair" )
KG_PQC(mceliece_6960119f, mceliece6960119f, "mceliece6960119f-keypair")
KG_PQC(mceliece_8192128,  mceliece8192128,  "mceliece8192128-keypair" )
KG_PQC(mceliece_8192128f, mceliece8192128f, "mceliece8192128f-keypair")

/* ---- SPHINCS+ (pqc names use "simple" suffix) ---- */
KG_PQC(sphincs_sha2_128f,  sphincssha2128fsimple,  "sphincssha2128fsimple-keypair" )
KG_PQC(sphincs_sha2_128s,  sphincssha2128ssimple,  "sphincssha2128ssimple-keypair" )
KG_PQC(sphincs_sha2_192f,  sphincssha2192fsimple,  "sphincssha2192fsimple-keypair" )
KG_PQC(sphincs_sha2_192s,  sphincssha2192ssimple,  "sphincssha2192ssimple-keypair" )
KG_PQC(sphincs_sha2_256f,  sphincssha2256fsimple,  "sphincssha2256fsimple-keypair" )
KG_PQC(sphincs_sha2_256s,  sphincssha2256ssimple,  "sphincssha2256ssimple-keypair" )
KG_PQC(sphincs_shake_128f, sphincsshake128fsimple, "sphincsshake128fsimple-keypair")
KG_PQC(sphincs_shake_128s, sphincsshake128ssimple, "sphincsshake128ssimple-keypair")
KG_PQC(sphincs_shake_192f, sphincsshake192fsimple, "sphincsshake192fsimple-keypair")
KG_PQC(sphincs_shake_192s, sphincsshake192ssimple, "sphincsshake192ssimple-keypair")
KG_PQC(sphincs_shake_256f, sphincsshake256fsimple, "sphincsshake256fsimple-keypair")
KG_PQC(sphincs_shake_256s, sphincsshake256ssimple, "sphincsshake256ssimple-keypair")

#undef KG_PQC

/* -----------------------------------------------------------------------
 * One-shot convenience wrappers
 *
 * KG_RANDOM(algo)    — keygen_<algo>_random(pk, sk)
 * KG_DRBG(algo)      — keygen_<algo>_drbg(seed, slen, label, pk, sk)
 * KG_PASSWORD(algo)  — keygen_<algo>_password(pwd, plen, salt, slen, params, pk, sk)
 * KG_HD(algo)        — keygen_<algo>_hd(master, mlen, path, pk, sk)
 *
 * The (uint8_t *) signature is compatible with all array parameters
 * because "T arr[N]" degrades to "T *" in function parameters.
 * --------------------------------------------------------------------- */

#define KG_RANDOM(algo)                                                        \
int keygen_##algo##_random(uint8_t *pk, uint8_t *sk) {                        \
    keygen_ctx_t *ctx = keygen_new_random();                                   \
    if (!ctx) return -1;                                                       \
    int r = keygen_##algo(ctx, pk, sk);                                        \
    keygen_free(ctx);                                                          \
    return r;                                                                  \
}

#define KG_DRBG(algo)                                                          \
int keygen_##algo##_drbg(const uint8_t *seed, size_t slen, const char *label, \
                          uint8_t *pk, uint8_t *sk) {                         \
    keygen_ctx_t *ctx = keygen_new_drbg(seed, slen, label);                   \
    if (!ctx) return -1;                                                       \
    int r = keygen_##algo(ctx, pk, sk);                                        \
    keygen_free(ctx);                                                          \
    return r;                                                                  \
}

#define KG_PASSWORD(algo)                                                      \
int keygen_##algo##_password(const uint8_t *pwd, size_t plen,                 \
                              const uint8_t *salt, size_t slen,               \
                              const keygen_argon2_params_t *params,           \
                              uint8_t *pk, uint8_t *sk) {                     \
    keygen_ctx_t *ctx = keygen_new_password(pwd, plen, salt, slen, params);   \
    if (!ctx) return -1;                                                       \
    int r = keygen_##algo(ctx, pk, sk);                                        \
    keygen_free(ctx);                                                          \
    return r;                                                                  \
}

#define KG_HD(algo)                                                            \
int keygen_##algo##_hd(const uint8_t *master, size_t mlen, const char *path,  \
                        uint8_t *pk, uint8_t *sk) {                           \
    keygen_ctx_t *ctx = keygen_new_hd(master, mlen, path);                    \
    if (!ctx) return -1;                                                       \
    int r = keygen_##algo(ctx, pk, sk);                                        \
    keygen_free(ctx);                                                          \
    return r;                                                                  \
}

#define KG_HASH(algo)                                                          \
int keygen_##algo##_hash(const uint8_t *seed, size_t slen,                    \
                          const uint8_t *ctx_data, size_t clen,               \
                          uint8_t *pk, uint8_t *sk) {                         \
    keygen_ctx_t *ctx = keygen_new_hash(seed, slen, ctx_data, clen);          \
    if (!ctx) return -1;                                                       \
    int r = keygen_##algo(ctx, pk, sk);                                        \
    keygen_free(ctx);                                                          \
    return r;                                                                  \
}

#define KG_KDF(algo)                                                           \
int keygen_##algo##_kdf(const uint8_t *ikm,  size_t ilen,                     \
                         const uint8_t *salt, size_t slen,                    \
                         const uint8_t *info, size_t flen,                    \
                         uint8_t *pk, uint8_t *sk) {                          \
    keygen_ctx_t *ctx = keygen_new_kdf(ikm, ilen, salt, slen, info, flen);    \
    if (!ctx) return -1;                                                       \
    int r = keygen_##algo(ctx, pk, sk);                                        \
    keygen_free(ctx);                                                          \
    return r;                                                                  \
}

#define KG_UDBF(algo)                                                          \
int keygen_##algo##_udbf(const uint8_t *entropy, size_t elen,                 \
                          uint8_t *pk, uint8_t *sk) {                         \
    keygen_ctx_t *ctx = keygen_new_udbf(entropy, elen, NULL);                 \
    if (!ctx) return -1;                                                       \
    int r = keygen_##algo(ctx, pk, sk);                                        \
    keygen_free(ctx);                                                          \
    return r;                                                                  \
}

/* Ed25519 — all seven modes */
KG_RANDOM  (ed25519)
KG_DRBG    (ed25519)
KG_PASSWORD(ed25519)
KG_HD      (ed25519)
KG_HASH    (ed25519)
KG_KDF     (ed25519)
KG_UDBF    (ed25519)

/* X25519 — all seven modes */
KG_RANDOM  (x25519)
KG_DRBG    (x25519)
KG_PASSWORD(x25519)
KG_HD      (x25519)
KG_HASH    (x25519)
KG_KDF     (x25519)
KG_UDBF    (x25519)

/* Ed448 — all seven modes */
KG_RANDOM  (ed448)
KG_DRBG    (ed448)
KG_PASSWORD(ed448)
KG_HD      (ed448)
KG_HASH    (ed448)
KG_KDF     (ed448)
KG_UDBF    (ed448)

/* X448 — all seven modes */
KG_RANDOM  (x448)
KG_DRBG    (x448)
KG_PASSWORD(x448)
KG_HD      (x448)
KG_HASH    (x448)
KG_KDF     (x448)
KG_UDBF    (x448)

/* Elligator2 — all seven modes */
KG_RANDOM   (elligator2)
KG_DRBG     (elligator2)
KG_PASSWORD (elligator2)
KG_HD       (elligator2)
KG_HASH     (elligator2)
KG_KDF      (elligator2)
KG_UDBF     (elligator2)

/* ML-KEM — all seven modes */
KG_RANDOM   (ml_kem_512)
KG_DRBG     (ml_kem_512)
KG_PASSWORD (ml_kem_512)
KG_HD       (ml_kem_512)
KG_HASH     (ml_kem_512)
KG_KDF      (ml_kem_512)
KG_UDBF     (ml_kem_512)

KG_RANDOM   (ml_kem_768)
KG_DRBG     (ml_kem_768)
KG_PASSWORD (ml_kem_768)
KG_HD       (ml_kem_768)
KG_HASH     (ml_kem_768)
KG_KDF      (ml_kem_768)
KG_UDBF     (ml_kem_768)

KG_RANDOM   (ml_kem_1024)
KG_DRBG     (ml_kem_1024)
KG_PASSWORD (ml_kem_1024)
KG_HD       (ml_kem_1024)
KG_HASH     (ml_kem_1024)
KG_KDF      (ml_kem_1024)
KG_UDBF     (ml_kem_1024)

/* ML-DSA — all seven modes */
KG_RANDOM   (ml_dsa_44)
KG_DRBG     (ml_dsa_44)
KG_PASSWORD (ml_dsa_44)
KG_HD       (ml_dsa_44)
KG_HASH     (ml_dsa_44)
KG_KDF      (ml_dsa_44)
KG_UDBF     (ml_dsa_44)

KG_RANDOM   (ml_dsa_65)
KG_DRBG     (ml_dsa_65)
KG_PASSWORD (ml_dsa_65)
KG_HD       (ml_dsa_65)
KG_HASH     (ml_dsa_65)
KG_KDF      (ml_dsa_65)
KG_UDBF     (ml_dsa_65)

KG_RANDOM   (ml_dsa_87)
KG_DRBG     (ml_dsa_87)
KG_PASSWORD (ml_dsa_87)
KG_HD       (ml_dsa_87)
KG_HASH     (ml_dsa_87)
KG_KDF      (ml_dsa_87)
KG_UDBF     (ml_dsa_87)

/* Falcon + Falcon-Padded — all seven modes */
KG_RANDOM   (falcon_512)
KG_DRBG     (falcon_512)
KG_PASSWORD (falcon_512)
KG_HD       (falcon_512)
KG_HASH     (falcon_512)
KG_KDF      (falcon_512)
KG_UDBF     (falcon_512)
KG_RANDOM   (falcon_1024)
KG_DRBG     (falcon_1024)
KG_PASSWORD (falcon_1024)
KG_HD       (falcon_1024)
KG_HASH     (falcon_1024)
KG_KDF      (falcon_1024)
KG_UDBF     (falcon_1024)
KG_RANDOM   (falcon_padded_512)
KG_DRBG     (falcon_padded_512)
KG_PASSWORD (falcon_padded_512)
KG_HD       (falcon_padded_512)
KG_HASH     (falcon_padded_512)
KG_KDF      (falcon_padded_512)
KG_UDBF     (falcon_padded_512)
KG_RANDOM   (falcon_padded_1024)
KG_DRBG     (falcon_padded_1024)
KG_PASSWORD (falcon_padded_1024)
KG_HD       (falcon_padded_1024)
KG_HASH     (falcon_padded_1024)
KG_KDF      (falcon_padded_1024)
KG_UDBF     (falcon_padded_1024)

/* SPHINCS+ — all seven modes */
KG_RANDOM   (sphincs_sha2_128f)
KG_DRBG     (sphincs_sha2_128f)
KG_PASSWORD (sphincs_sha2_128f)
KG_HD       (sphincs_sha2_128f)
KG_HASH     (sphincs_sha2_128f)
KG_KDF      (sphincs_sha2_128f)
KG_UDBF     (sphincs_sha2_128f)
KG_RANDOM   (sphincs_sha2_128s)
KG_DRBG     (sphincs_sha2_128s)
KG_PASSWORD (sphincs_sha2_128s)
KG_HD       (sphincs_sha2_128s)
KG_HASH     (sphincs_sha2_128s)
KG_KDF      (sphincs_sha2_128s)
KG_UDBF     (sphincs_sha2_128s)
KG_RANDOM   (sphincs_sha2_192f)
KG_DRBG     (sphincs_sha2_192f)
KG_PASSWORD (sphincs_sha2_192f)
KG_HD       (sphincs_sha2_192f)
KG_HASH     (sphincs_sha2_192f)
KG_KDF      (sphincs_sha2_192f)
KG_UDBF     (sphincs_sha2_192f)
KG_RANDOM   (sphincs_sha2_192s)
KG_DRBG     (sphincs_sha2_192s)
KG_PASSWORD (sphincs_sha2_192s)
KG_HD       (sphincs_sha2_192s)
KG_HASH     (sphincs_sha2_192s)
KG_KDF      (sphincs_sha2_192s)
KG_UDBF     (sphincs_sha2_192s)
KG_RANDOM   (sphincs_sha2_256f)
KG_DRBG     (sphincs_sha2_256f)
KG_PASSWORD (sphincs_sha2_256f)
KG_HD       (sphincs_sha2_256f)
KG_HASH     (sphincs_sha2_256f)
KG_KDF      (sphincs_sha2_256f)
KG_UDBF     (sphincs_sha2_256f)
KG_RANDOM   (sphincs_sha2_256s)
KG_DRBG     (sphincs_sha2_256s)
KG_PASSWORD (sphincs_sha2_256s)
KG_HD       (sphincs_sha2_256s)
KG_HASH     (sphincs_sha2_256s)
KG_KDF      (sphincs_sha2_256s)
KG_UDBF     (sphincs_sha2_256s)
KG_RANDOM   (sphincs_shake_128f)
KG_DRBG     (sphincs_shake_128f)
KG_PASSWORD (sphincs_shake_128f)
KG_HD       (sphincs_shake_128f)
KG_HASH     (sphincs_shake_128f)
KG_KDF      (sphincs_shake_128f)
KG_UDBF     (sphincs_shake_128f)
KG_RANDOM   (sphincs_shake_128s)
KG_DRBG     (sphincs_shake_128s)
KG_PASSWORD (sphincs_shake_128s)
KG_HD       (sphincs_shake_128s)
KG_HASH     (sphincs_shake_128s)
KG_KDF      (sphincs_shake_128s)
KG_UDBF     (sphincs_shake_128s)
KG_RANDOM   (sphincs_shake_192f)
KG_DRBG     (sphincs_shake_192f)
KG_PASSWORD (sphincs_shake_192f)
KG_HD       (sphincs_shake_192f)
KG_HASH     (sphincs_shake_192f)
KG_KDF      (sphincs_shake_192f)
KG_UDBF     (sphincs_shake_192f)
KG_RANDOM   (sphincs_shake_192s)
KG_DRBG     (sphincs_shake_192s)
KG_PASSWORD (sphincs_shake_192s)
KG_HD       (sphincs_shake_192s)
KG_HASH     (sphincs_shake_192s)
KG_KDF      (sphincs_shake_192s)
KG_UDBF     (sphincs_shake_192s)
KG_RANDOM   (sphincs_shake_256f)
KG_DRBG     (sphincs_shake_256f)
KG_PASSWORD (sphincs_shake_256f)
KG_HD       (sphincs_shake_256f)
KG_HASH     (sphincs_shake_256f)
KG_KDF      (sphincs_shake_256f)
KG_UDBF     (sphincs_shake_256f)
KG_RANDOM   (sphincs_shake_256s)
KG_DRBG     (sphincs_shake_256s)
KG_PASSWORD (sphincs_shake_256s)
KG_HD       (sphincs_shake_256s)
KG_HASH     (sphincs_shake_256s)
KG_KDF      (sphincs_shake_256s)
KG_UDBF     (sphincs_shake_256s)

/* HQC — all seven modes */
KG_RANDOM   (hqc_128)
KG_DRBG     (hqc_128)
KG_PASSWORD (hqc_128)
KG_HD       (hqc_128)
KG_HASH     (hqc_128)
KG_KDF      (hqc_128)
KG_UDBF     (hqc_128)
KG_RANDOM   (hqc_192)
KG_DRBG     (hqc_192)
KG_PASSWORD (hqc_192)
KG_HD       (hqc_192)
KG_HASH     (hqc_192)
KG_KDF      (hqc_192)
KG_UDBF     (hqc_192)
KG_RANDOM   (hqc_256)
KG_DRBG     (hqc_256)
KG_PASSWORD (hqc_256)
KG_HD       (hqc_256)
KG_HASH     (hqc_256)
KG_KDF      (hqc_256)
KG_UDBF     (hqc_256)

/* Classic McEliece — all seven modes */
KG_RANDOM   (mceliece_348864)
KG_DRBG     (mceliece_348864)
KG_PASSWORD (mceliece_348864)
KG_HD       (mceliece_348864)
KG_HASH     (mceliece_348864)
KG_KDF      (mceliece_348864)
KG_UDBF     (mceliece_348864)
KG_RANDOM   (mceliece_348864f)
KG_DRBG     (mceliece_348864f)
KG_PASSWORD (mceliece_348864f)
KG_HD       (mceliece_348864f)
KG_HASH     (mceliece_348864f)
KG_KDF      (mceliece_348864f)
KG_UDBF     (mceliece_348864f)
KG_RANDOM   (mceliece_460896)
KG_DRBG     (mceliece_460896)
KG_PASSWORD (mceliece_460896)
KG_HD       (mceliece_460896)
KG_HASH     (mceliece_460896)
KG_KDF      (mceliece_460896)
KG_UDBF     (mceliece_460896)
KG_RANDOM   (mceliece_460896f)
KG_DRBG     (mceliece_460896f)
KG_PASSWORD (mceliece_460896f)
KG_HD       (mceliece_460896f)
KG_HASH     (mceliece_460896f)
KG_KDF      (mceliece_460896f)
KG_UDBF     (mceliece_460896f)
KG_RANDOM   (mceliece_6688128)
KG_DRBG     (mceliece_6688128)
KG_PASSWORD (mceliece_6688128)
KG_HD       (mceliece_6688128)
KG_HASH     (mceliece_6688128)
KG_KDF      (mceliece_6688128)
KG_UDBF     (mceliece_6688128)
KG_RANDOM   (mceliece_6688128f)
KG_DRBG     (mceliece_6688128f)
KG_PASSWORD (mceliece_6688128f)
KG_HD       (mceliece_6688128f)
KG_HASH     (mceliece_6688128f)
KG_KDF      (mceliece_6688128f)
KG_UDBF     (mceliece_6688128f)
KG_RANDOM   (mceliece_6960119)
KG_DRBG     (mceliece_6960119)
KG_PASSWORD (mceliece_6960119)
KG_HD       (mceliece_6960119)
KG_HASH     (mceliece_6960119)
KG_KDF      (mceliece_6960119)
KG_UDBF     (mceliece_6960119)
KG_RANDOM   (mceliece_6960119f)
KG_DRBG     (mceliece_6960119f)
KG_PASSWORD (mceliece_6960119f)
KG_HD       (mceliece_6960119f)
KG_HASH     (mceliece_6960119f)
KG_KDF      (mceliece_6960119f)
KG_UDBF     (mceliece_6960119f)
KG_RANDOM   (mceliece_8192128)
KG_DRBG     (mceliece_8192128)
KG_PASSWORD (mceliece_8192128)
KG_HD       (mceliece_8192128)
KG_HASH     (mceliece_8192128)
KG_KDF      (mceliece_8192128)
KG_UDBF     (mceliece_8192128)
KG_RANDOM   (mceliece_8192128f)
KG_DRBG     (mceliece_8192128f)
KG_PASSWORD (mceliece_8192128f)
KG_HD       (mceliece_8192128f)
KG_HASH     (mceliece_8192128f)
KG_KDF      (mceliece_8192128f)
KG_UDBF     (mceliece_8192128f)

#undef KG_RANDOM
#undef KG_DRBG
#undef KG_PASSWORD
#undef KG_HD
#undef KG_HASH
#undef KG_KDF
#undef KG_UDBF
