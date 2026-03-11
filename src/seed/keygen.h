#ifndef NEXTSSL_SEED_KEYGEN_H
#define NEXTSSL_SEED_KEYGEN_H

#include <stddef.h>
#include <stdint.h>
#include "password/seed_password.h" /* keygen_argon2_params_t */

/*
 * keygen.h — Public key generation API (Task 104)
 *
 * Two usage patterns:
 *
 *   OBJECT PATTERN (multi-key from one root, full control):
 *       keygen_ctx_t *ctx = keygen_new_drbg(seed, slen, "label");
 *       keygen_ed25519(ctx, pk1, sk1);
 *       keygen_ml_kem_1024(ctx, pk2, sk2);
 *       keygen_free(ctx);
 *
 *   ONE-SHOT PATTERN (single keypair, no context boilerplate):
 *       keygen_ed25519_random(pk, sk);
 *       keygen_ml_kem_1024_drbg(seed, slen, "label", pk, sk);
 *
 * The seed never crosses the API boundary as raw bytes:
 *   - All seeding modes condition input through HKDF before DRBG init.
 *   - Coin bytes are stack-local inside each wrapper and wiped on return.
 *   - KEYGEN_RANDOM bypasses DRBG entirely — goes straight to OS RNG.
 */

typedef struct keygen_ctx keygen_ctx_t; /* opaque */

/* -----------------------------------------------------------------------
 * Context factories — choose ONE seeding mode at construction time.
 * All return NULL on allocation or derivation failure.
 * --------------------------------------------------------------------- */

/* OS random (non-deterministic) */
keygen_ctx_t *keygen_new_random(void);

/* HMAC-DRBG seeded from caller material; HKDF conditions the input */
keygen_ctx_t *keygen_new_drbg(const uint8_t *seed, size_t seed_len,const char *label);

/* SHA-512 CTR derivation: keygen_new_hash(seed, slen, ctx, clen) */
keygen_ctx_t *keygen_new_hash(const uint8_t *seed, size_t seed_len,const uint8_t *ctx, size_t ctx_len);

/* HKDF(ikm, salt, info) */
keygen_ctx_t *keygen_new_kdf(const uint8_t *ikm, size_t ikm_len,const uint8_t *salt, size_t salt_len,const uint8_t *info, size_t info_len);

/* Argon2id(password, salt, params) — for password-protected deterministic keys */
keygen_ctx_t *keygen_new_password(const uint8_t *pwd, size_t pwd_len,const uint8_t *salt, size_t salt_len,const keygen_argon2_params_t *params);

/* UDBF: user-supplied entropy buffer (stateful; use object pattern only) */
keygen_ctx_t *keygen_new_udbf(const uint8_t *entropy, size_t ent_len,const char *label);

/* BIP32-style hierarchical derivation from master seed + path */
keygen_ctx_t *keygen_new_hd(const uint8_t *master_seed, size_t seed_len,const char *path);

/* Wipe all internal state and free */
void keygen_free(keygen_ctx_t *ctx);

/* -----------------------------------------------------------------------
 * Object-pattern key generators.
 * Each one extracts internal coin bytes and wipes them before returning.
 * The caller only receives (pk, sk).
 * --------------------------------------------------------------------- */

/* Raw fill — restricted; NOT exported in primary/ public headers */
int keygen_raw(keygen_ctx_t *ctx, const char *label,uint8_t *out, size_t out_len);

/* Classic ECC */
int keygen_ed25519(keygen_ctx_t *ctx, uint8_t pk[32], uint8_t sk[64]);
int keygen_x25519(keygen_ctx_t *ctx, uint8_t pk[32], uint8_t sk[32]);
int keygen_ed448(keygen_ctx_t *ctx, uint8_t pk[57], uint8_t sk[57]);
int keygen_x448(keygen_ctx_t *ctx, uint8_t pk[56], uint8_t sk[56]);

/* Elligator2 — obfuscated X25519 keypair (hidden[32] + sk[32]) */
int keygen_elligator2(keygen_ctx_t *ctx, uint8_t hidden[32], uint8_t sk[32]);

/* PQC KEM */
int keygen_ml_kem_512(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_768(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_1024(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_hqc_128(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_hqc_192(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_hqc_256(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);

/* PQC Signature */
int keygen_ml_dsa_44(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_65(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_87(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_falcon_512(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s(keygen_ctx_t *ctx, uint8_t *pk, uint8_t *sk);

/* -----------------------------------------------------------------------
 * One-shot convenience API — context created and freed internally.
 * Naming: keygen_<algo>_<mode>(mode_params..., pk, sk)
 * Available modes: _random, _drbg, _password, _hd, _hash, _kdf, _udbf
 * --------------------------------------------------------------------- */

/* Ed25519 */
int keygen_ed25519_random(uint8_t pk[32], uint8_t sk[64]);
int keygen_ed25519_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t pk[32], uint8_t sk[64]);
int keygen_ed25519_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t pk[32], uint8_t sk[64]);
int keygen_ed25519_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t pk[32], uint8_t sk[64]);
int keygen_ed25519_hash(const uint8_t *seed, size_t slen,const uint8_t *ctx_data, size_t clen,uint8_t pk[32], uint8_t sk[64]);
int keygen_ed25519_kdf(const uint8_t *ikm, size_t ilen,const uint8_t *salt, size_t slen,const uint8_t *info, size_t flen,uint8_t pk[32], uint8_t sk[64]);
int keygen_ed25519_udbf(const uint8_t *entropy, size_t elen,uint8_t pk[32], uint8_t sk[64]);

/* X25519 */
int keygen_x25519_random(uint8_t pk[32], uint8_t sk[32]);
int keygen_x25519_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t pk[32], uint8_t sk[32]);
int keygen_x25519_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t pk[32], uint8_t sk[32]);
int keygen_x25519_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t pk[32], uint8_t sk[32]);
int keygen_x25519_hash(const uint8_t *seed, size_t slen,const uint8_t *ctx_data, size_t clen,uint8_t pk[32], uint8_t sk[32]);
int keygen_x25519_kdf(const uint8_t *ikm, size_t ilen,const uint8_t *salt, size_t slen,const uint8_t *info, size_t flen,uint8_t pk[32], uint8_t sk[32]);
int keygen_x25519_udbf(const uint8_t *entropy, size_t elen,uint8_t pk[32], uint8_t sk[32]);

/* Ed448 */
int keygen_ed448_random(uint8_t pk[57], uint8_t sk[57]);
int keygen_ed448_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t pk[57], uint8_t sk[57]);
int keygen_ed448_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t pk[57], uint8_t sk[57]);
int keygen_ed448_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t pk[57], uint8_t sk[57]);
int keygen_ed448_hash(const uint8_t *seed, size_t slen,const uint8_t *ctx_data, size_t clen,uint8_t pk[57], uint8_t sk[57]);
int keygen_ed448_kdf(const uint8_t *ikm, size_t ilen,const uint8_t *salt, size_t slen,const uint8_t *info, size_t flen,uint8_t pk[57], uint8_t sk[57]);
int keygen_ed448_udbf(const uint8_t *entropy, size_t elen,uint8_t pk[57], uint8_t sk[57]);

/* X448 */
int keygen_x448_random(uint8_t pk[56], uint8_t sk[56]);
int keygen_x448_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t pk[56], uint8_t sk[56]);
int keygen_x448_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t pk[56], uint8_t sk[56]);
int keygen_x448_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t pk[56], uint8_t sk[56]);
int keygen_x448_hash(const uint8_t *seed, size_t slen,const uint8_t *ctx_data, size_t clen,uint8_t pk[56], uint8_t sk[56]);
int keygen_x448_kdf(const uint8_t *ikm, size_t ilen,const uint8_t *salt, size_t slen,const uint8_t *info, size_t flen,uint8_t pk[56], uint8_t sk[56]);
int keygen_x448_udbf(const uint8_t *entropy, size_t elen,uint8_t pk[56], uint8_t sk[56]);

/* Elligator2 */
int keygen_elligator2_random(uint8_t hidden[32], uint8_t sk[32]);
int keygen_elligator2_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t hidden[32], uint8_t sk[32]);
int keygen_elligator2_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t hidden[32], uint8_t sk[32]);
int keygen_elligator2_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t hidden[32], uint8_t sk[32]);
int keygen_elligator2_hash(const uint8_t *seed, size_t slen,const uint8_t *ctx_data, size_t clen,uint8_t hidden[32], uint8_t sk[32]);
int keygen_elligator2_kdf(const uint8_t *ikm, size_t ilen,const uint8_t *salt, size_t slen,const uint8_t *info, size_t flen,uint8_t hidden[32], uint8_t sk[32]);
int keygen_elligator2_udbf(const uint8_t *entropy, size_t elen,uint8_t hidden[32], uint8_t sk[32]);

/* ML-KEM-512 */
int keygen_ml_kem_512_random(uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_512_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_512_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_512_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_512_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_512_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_512_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

/* ML-KEM-768 */
int keygen_ml_kem_768_random(uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_768_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_768_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_768_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_768_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_768_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_768_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

/* ML-KEM-1024 */
int keygen_ml_kem_1024_random(uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_1024_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_1024_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_1024_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_1024_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_1024_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_ml_kem_1024_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

/* ML-DSA-44/65/87 */
int keygen_ml_dsa_44_random(uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_44_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_44_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_44_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_44_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_44_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_44_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

int keygen_ml_dsa_65_random(uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_65_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_65_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_65_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_65_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_65_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_65_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

int keygen_ml_dsa_87_random(uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_87_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_87_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_87_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_87_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_87_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_ml_dsa_87_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

/* Falcon-512/1024 and Falcon-Padded-512/1024 */
int keygen_falcon_512_random(uint8_t *pk, uint8_t *sk);
int keygen_falcon_512_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_falcon_512_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_falcon_512_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_falcon_512_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_512_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_512_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024_random(uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_1024_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512_random(uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_512_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024_random(uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024_drbg(const uint8_t *seed, size_t slen, const char *label,uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024_password(const uint8_t *pwd, size_t plen,const uint8_t *salt, size_t slen,const keygen_argon2_params_t *params,uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024_hd(const uint8_t *master, size_t mlen, const char *path,uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_falcon_padded_1024_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

/* SPHINCS+, HQC, McEliece — _random, _drbg, _password, _hd, _hash, _kdf, _udbf */
int keygen_sphincs_sha2_128f_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_128s_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_192s_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_sha2_256s_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_128s_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_192s_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s_random(uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_sphincs_shake_256s_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

int keygen_hqc_128_random(uint8_t *pk, uint8_t *sk);
int keygen_hqc_128_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_hqc_128_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_hqc_128_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_hqc_128_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_128_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_128_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_192_random(uint8_t *pk, uint8_t *sk);
int keygen_hqc_192_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_hqc_192_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_hqc_192_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_hqc_192_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_192_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_192_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_256_random(uint8_t *pk, uint8_t *sk);
int keygen_hqc_256_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_hqc_256_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_hqc_256_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_hqc_256_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_256_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_hqc_256_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

int keygen_mceliece_348864_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_348864f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_460896f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6688128f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_6960119f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f_random(uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f_drbg(const uint8_t *seed, size_t slen, const char *label, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f_password(const uint8_t *pwd, size_t plen, const uint8_t *salt, size_t slen, const keygen_argon2_params_t *params, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f_hd(const uint8_t *master, size_t mlen, const char *path, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f_hash(const uint8_t *seed, size_t slen, const uint8_t *ctx_data, size_t clen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f_kdf(const uint8_t *ikm, size_t ilen, const uint8_t *salt, size_t slen, const uint8_t *info, size_t flen, uint8_t *pk, uint8_t *sk);
int keygen_mceliece_8192128f_udbf(const uint8_t *entropy, size_t elen, uint8_t *pk, uint8_t *sk);

#endif /* NEXTSSL_SEED_KEYGEN_H */
