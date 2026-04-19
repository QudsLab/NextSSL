/* root_hash.c — Hash API Implementation (Plan 405)
 *
 * Thin export layer over hash/interface/hash_registry.c.
 */
#include "root_hash.h"
#include "../../hash/interface/hash_registry.h"
#include <string.h>

static const char *s_algo_list[HASH_REGISTRY_MAX + 1];
static int s_algo_list_ready = 0;

static void root_hash_build_algo_list(void)
{
    if (s_algo_list_ready) {
        return;
    }

    hash_registry_init();
    for (size_t i = 0; i < hash_registry_count() && i < HASH_REGISTRY_MAX; ++i) {
        const hash_ops_t *ops = hash_registry_at(i);
        s_algo_list[i] = ops ? ops->name : NULL;
    }
    s_algo_list[hash_registry_count()] = NULL;
    s_algo_list_ready = 1;
}

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
    root_hash_build_algo_list();
    return s_algo_list;
}
