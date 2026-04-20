/* hash_root.h — Way 3: Per-algorithm typed root functions (Plan 40002)
 *
 * One function per algorithm.  Each function creates the adapter internally,
 * runs the hash/KDF, destroys the adapter, and returns the result.
 *
 * Plain hash functions:
 *   int nextssl_sha256(data, data_len, out, out_len);
 *
 * KDF functions accept algorithm-specific parameters. Pass 0 / NULL only for
 * parameters documented as defaultable.
 *
 * Return values:
 *   0   — success
 *  -1   — allocation failure
 *  -2   — KDF/hash computation failure
 */
#ifndef HASH_ROOT_H
#define HASH_ROOT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =====================================================================
 * Plain hash functions — 34 algorithms
 * Each produces min(out_len, digest_size) bytes; no config needed.
 * ===================================================================== */

/* ---- BLAKE family ---- */
int nextssl_blake2b  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_blake2s  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_blake3   (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);

/* ---- SHA-2 / SM3 ---- */
int nextssl_sha224     (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha256     (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha384     (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha512     (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha512_224 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha512_256 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sm3        (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);

/* ---- Legacy / weak ⚠️ ---- */
int nextssl_has160    (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_md2       (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_md4       (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_md5       (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_nt        (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_ripemd128 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_ripemd160 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_ripemd256 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_ripemd320 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha0      (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha1      (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_whirlpool (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);

/* ---- SHA-3 / Keccak / Sponge ---- */
int nextssl_keccak256 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha3_224  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha3_256  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha3_384  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_sha3_512  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);

/* ---- XOF ---- */
int nextssl_shake128  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_shake256  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);

/* ---- Skein ---- */
int nextssl_skein256  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_skein512  (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_skein1024 (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);

/* ---- KMAC ---- */
int nextssl_kmac128   (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);
int nextssl_kmac256   (const uint8_t *d, size_t dl, uint8_t *o, size_t ol);

/* =====================================================================
 * KDF functions — 9+ algorithms
 * Pass 0 / NULL for any parameter to use built-in safe defaults.
 * ===================================================================== */

/* ---- Argon2 family ---- */
int nextssl_argon2id(const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint32_t memory, uint32_t iterations, uint32_t parallelism,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len);

int nextssl_argon2i (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint32_t memory, uint32_t iterations, uint32_t parallelism,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len);

int nextssl_argon2d (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint32_t memory, uint32_t iterations, uint32_t parallelism,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len);

/* ---- Scrypt ---- */
int nextssl_scrypt  (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint64_t N, uint32_t r, uint32_t p,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len);

/* ---- Yescrypt ---- */
int nextssl_yescrypt(const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint64_t N, uint32_t r, uint32_t p,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len);

/* ---- Bcrypt ---- */
int nextssl_bcrypt  (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint32_t work_factor,
                     const uint8_t *salt, size_t salt_len);

/* ---- Catena ---- */
int nextssl_catena  (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint8_t lambda, uint8_t garlic,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len);

/* ---- Lyra2 ---- */
int nextssl_lyra2   (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint64_t t_cost, uint32_t nrows, uint32_t ncols,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len);

/* ---- Balloon ---- */
int nextssl_balloon (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint32_t s_cost, uint32_t t_cost, uint32_t n_threads,
                     const uint8_t *salt, size_t salt_len);

/* ---- Pomelo ---- */
int nextssl_pomelo  (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     unsigned int t_cost, unsigned int m_cost,
                     size_t key_length, const uint8_t *salt, size_t salt_len);

/* ---- Makwa ---- */
int nextssl_makwa   (const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint32_t work_factor, size_t key_length,
                     const uint8_t *salt, size_t salt_len);

#ifdef __cplusplus
}
#endif

#endif /* HASH_ROOT_H */
