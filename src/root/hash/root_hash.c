/* root_hash.c — Hash API Implementation (Plan 405)
 *
 * Thin export layer over hash/interface/hash_registry.c.
 */
#include "root_hash.h"
#include "../../hash/interface/hash_registry.h"
#include <string.h>

/* Static NULL-terminated list of all canonical algorithm names.
 * Must match the 41+ entries in hash_registry.c. */
static const char *s_algo_list[] = {
    /* Blake */
    "blake2b", "blake2s", "blake3",
    /* Fast / SHA-2 */
    "sha224", "sha256", "sha384", "sha512",
    "sha512-224", "sha512/224", "sha512-256", "sha512/256", "sm3",
    /* Legacy */
    "has160", "md2", "md4", "md5", "nt", "nthash",
    "ripemd128", "ripemd160", "ripemd256", "ripemd320",
    "sha0", "sha1", "tiger", "whirlpool",
    /* Memory-Hard */
    "argon2id", "argon2i", "argon2d",
    "scrypt",
    "yescrypt",
    "catena",
    "lyra2",
    "bcrypt",
    /* Sponge / SHA-3 */
    "keccak256", "sha3-224", "sha3-256", "sha3-384", "sha3-512",
    /* XOF */
    "shake128", "shake256",
    /* Skein */
    "skein256", "skein512", "skein1024",
    /* KMAC */
    "kmac128", "kmac256",
    NULL  /* sentinel */
};

/* -------------------------------------------------------------------------
 * nextssl_hash_compute
 * -------------------------------------------------------------------------*/
int nextssl_hash_compute(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    uint8_t       *out,
    size_t        *out_len)
{
    const hash_ops_t *ops;
    uint8_t ctx[HASH_OPS_CTX_MAX];

    if (!algo || !out || !out_len) {
        return -1;
    }

    hash_registry_init();
    ops = hash_lookup(algo);
    if (!ops) {
        return -1;  /* Unknown algorithm */
    }

    if (*out_len < ops->digest_size) {
        return -1;  /* Output buffer too small */
    }

    ops->init(ctx);
    if (data && data_len > 0) {
        ops->update(ctx, data, data_len);
    }
    ops->final(ctx, out);

    *out_len = ops->digest_size;

    /* Wipe context */
    volatile uint8_t *p = (volatile uint8_t *)ctx;
    for (size_t i = 0; i < sizeof(ctx); i++) p[i] = 0;

    return 0;
}

/* -------------------------------------------------------------------------
 * nextssl_hash_digest_size
 * -------------------------------------------------------------------------*/
size_t nextssl_hash_digest_size(const char *algo)
{
    const hash_ops_t *ops;
    if (!algo) return 0;
    hash_registry_init();
    ops = hash_lookup(algo);
    return ops ? ops->digest_size : 0;
}

/* -------------------------------------------------------------------------
 * nextssl_hash_block_size
 * -------------------------------------------------------------------------*/
size_t nextssl_hash_block_size(const char *algo)
{
    const hash_ops_t *ops;
    if (!algo) return 0;
    hash_registry_init();
    ops = hash_lookup(algo);
    return ops ? ops->block_size : 0;
}

/* -------------------------------------------------------------------------
 * nextssl_hash_list
 * -------------------------------------------------------------------------*/
const char **nextssl_hash_list(void)
{
    return s_algo_list;
}
