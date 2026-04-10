/* hash_root.c — Way 3: Per-algorithm typed root functions (Plan 40002)
 *
 * Each function: create adapter → (config) → hash_fn → destroy.
 * All memory is allocated/freed within the call; no user-managed state.
 */
#include "hash_root.h"
#include "../adapters/hash_adapter.h"
#include "../adapters/plain_hash_adapter.h"
#include "../adapters/kdf_adapters.h"
#include <stdlib.h>

/* ---- Shared helper for plain-hash root functions ---- */
#define PLAIN_ROOT(fn, create_fn) \
int fn(const uint8_t *d, size_t dl, uint8_t *o, size_t ol) { \
    hash_adapter_t *a = create_fn(); \
    if (!a) return -1; \
    int rc = a->hash_fn(a->impl, d, dl, o, ol); \
    hash_adapter_free(a); \
    return (rc == 0) ? 0 : -2; \
}

/* =====================================================================
 * Plain hash root functions (34)
 * ===================================================================== */

PLAIN_ROOT(nextssl_blake2b,   blake2b_adapter_create)
PLAIN_ROOT(nextssl_blake2s,   blake2s_adapter_create)
PLAIN_ROOT(nextssl_blake3,    blake3_adapter_create)

PLAIN_ROOT(nextssl_sha224,     sha224_adapter_create)
PLAIN_ROOT(nextssl_sha256,     sha256_adapter_create)
PLAIN_ROOT(nextssl_sha384,     sha384_adapter_create)
PLAIN_ROOT(nextssl_sha512,     sha512_adapter_create)
PLAIN_ROOT(nextssl_sha512_224, sha512_224_adapter_create)
PLAIN_ROOT(nextssl_sha512_256, sha512_256_adapter_create)
PLAIN_ROOT(nextssl_sm3,        sm3_adapter_create)

PLAIN_ROOT(nextssl_has160,    has160_adapter_create)
PLAIN_ROOT(nextssl_md2,       md2_adapter_create)
PLAIN_ROOT(nextssl_md4,       md4_adapter_create)
PLAIN_ROOT(nextssl_md5,       md5_adapter_create)
PLAIN_ROOT(nextssl_nt,        nt_adapter_create)
PLAIN_ROOT(nextssl_ripemd128, ripemd128_adapter_create)
PLAIN_ROOT(nextssl_ripemd160, ripemd160_adapter_create)
PLAIN_ROOT(nextssl_ripemd256, ripemd256_adapter_create)
PLAIN_ROOT(nextssl_ripemd320, ripemd320_adapter_create)
PLAIN_ROOT(nextssl_sha0,      sha0_adapter_create)
PLAIN_ROOT(nextssl_sha1,      sha1_adapter_create)
PLAIN_ROOT(nextssl_whirlpool, whirlpool_adapter_create)

PLAIN_ROOT(nextssl_keccak256, keccak256_adapter_create)
PLAIN_ROOT(nextssl_sha3_224,  sha3_224_adapter_create)
PLAIN_ROOT(nextssl_sha3_256,  sha3_256_adapter_create)
PLAIN_ROOT(nextssl_sha3_384,  sha3_384_adapter_create)
PLAIN_ROOT(nextssl_sha3_512,  sha3_512_adapter_create)

PLAIN_ROOT(nextssl_shake128,  shake128_adapter_create)
PLAIN_ROOT(nextssl_shake256,  shake256_adapter_create)

PLAIN_ROOT(nextssl_skein256,  skein256_adapter_create)
PLAIN_ROOT(nextssl_skein512,  skein512_adapter_create)
PLAIN_ROOT(nextssl_skein1024, skein1024_adapter_create)

PLAIN_ROOT(nextssl_kmac128,   kmac128_adapter_create)
PLAIN_ROOT(nextssl_kmac256,   kmac256_adapter_create)

/* =====================================================================
 * KDF root functions (9 + 3 conditional)
 * ===================================================================== */

int nextssl_argon2id(const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint32_t memory, uint32_t iterations, uint32_t parallelism,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = argon2id_adapter_create(); if (!a) return -1;
    argon2id_adapter_config(a, memory, iterations, parallelism, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_argon2i(const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_len,
                    uint32_t memory, uint32_t iterations, uint32_t parallelism,
                    uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = argon2i_adapter_create(); if (!a) return -1;
    argon2i_adapter_config(a, memory, iterations, parallelism, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_argon2d(const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_len,
                    uint32_t memory, uint32_t iterations, uint32_t parallelism,
                    uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = argon2d_adapter_create(); if (!a) return -1;
    argon2d_adapter_config(a, memory, iterations, parallelism, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_argon2(const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len,
                   uint32_t memory, uint32_t iterations, uint32_t parallelism,
                   uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = argon2_adapter_create(); if (!a) return -1;
    argon2_adapter_config(a, memory, iterations, parallelism, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_scrypt(const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len,
                   uint64_t N, uint32_t r, uint32_t p,
                   uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = scrypt_adapter_create(); if (!a) return -1;
    scrypt_adapter_config(a, N, r, p, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_yescrypt(const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t out_len,
                     uint64_t N, uint32_t r, uint32_t p,
                     uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = yescrypt_adapter_create(); if (!a) return -1;
    yescrypt_adapter_config(a, N, r, p, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_bcrypt(const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len,
                   uint32_t work_factor,
                   const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = bcrypt_adapter_create(); if (!a) return -1;
    bcrypt_adapter_config(a, work_factor, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_catena(const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len,
                   uint8_t lambda, uint8_t garlic,
                   uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = catena_adapter_create(); if (!a) return -1;
    catena_adapter_config(a, lambda, garlic, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

int nextssl_lyra2(const uint8_t *data, size_t data_len,
                  uint8_t *out, size_t out_len,
                  uint64_t t_cost, uint32_t nrows, uint32_t ncols,
                  uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = lyra2_adapter_create(); if (!a) return -1;
    lyra2_adapter_config(a, t_cost, nrows, ncols, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}

#ifdef NEXTSSL_HAS_BALLOON
int nextssl_balloon(const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t out_len,
                    uint32_t s_cost, uint32_t t_cost, uint32_t n_threads,
                    const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = balloon_adapter_create(); if (!a) return -1;
    balloon_adapter_config(a, s_cost, t_cost, n_threads, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}
#endif

#ifdef NEXTSSL_HAS_POMELO
int nextssl_pomelo(const uint8_t *data, size_t data_len,
                   uint8_t *out, size_t out_len,
                   unsigned int t_cost, unsigned int m_cost,
                   uint32_t key_length, const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = pomelo_adapter_create(); if (!a) return -1;
    pomelo_adapter_config(a, t_cost, m_cost, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}
#endif

#ifdef NEXTSSL_HAS_MAKWA
int nextssl_makwa(const uint8_t *data, size_t data_len,
                  uint8_t *out, size_t out_len,
                  uint32_t work_factor, uint32_t key_length,
                  const uint8_t *salt, size_t salt_len)
{
    hash_adapter_t *a = makwa_adapter_create(); if (!a) return -1;
    makwa_adapter_config(a, work_factor, key_length, salt, salt_len);
    int rc = a->hash_fn(a->impl, data, data_len, out, out_len);
    hash_adapter_free(a); return (rc == 0) ? 0 : -2;
}
#endif
