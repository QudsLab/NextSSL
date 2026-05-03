/* root_hash.c — Hash API Implementation (Plan 405)
 *
 * Thin export layer over hash/interface/hash_registry.c.
 */
#include "root_hash.h"
#include "blake2b.h"
#include "../../hash/interface/hash_registry.h"
#include "skeinApi.h"
#include "shake.h"
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

static int root_hash_compute_variable(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    uint8_t       *out,
    size_t        *out_len)
{
    size_t requested = *out_len;

    if (requested == 0) {
        return -1;
    }

    if (strcmp(algo, "blake2b") == 0) {
        BLAKE2B_CTX ctx;

        if (requested > BLAKE2B_OUTBYTES || blake2b_init(&ctx, requested) != 0) {
            return -1;
        }
        if (data && data_len > 0) {
            blake2b_update(&ctx, data, data_len);
        }
        if (blake2b_final(&ctx, out, requested) != 0) {
            return -1;
        }
        *out_len = requested;
        return 0;
    }

    if (strcmp(algo, "shake128") == 0) {
        shake128_hash(data, data_len, out, requested);
        *out_len = requested;
        return 0;
    }

    if (strcmp(algo, "shake256") == 0) {
        shake256_hash(data, data_len, out, requested);
        *out_len = requested;
        return 0;
    }

    if (strcmp(algo, "skein1024") == 0) {
        SkeinCtx_t ctx;

        if (skeinCtxPrepare(&ctx, Skein1024) != SKEIN_SUCCESS) {
            return -1;
        }
        if (skeinInit(&ctx, requested * 8) != SKEIN_SUCCESS) {
            return -1;
        }
        if (data && data_len > 0 && skeinUpdate(&ctx, data, data_len) != SKEIN_SUCCESS) {
            return -1;
        }
        if (skeinFinal(&ctx, out) != SKEIN_SUCCESS) {
            return -1;
        }
        *out_len = requested;
        return 0;
    }

    return 1;
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
    int variable_rc;

    if (!algo || !out || !out_len) {
        return -1;
    }

    variable_rc = root_hash_compute_variable(algo, data, data_len, out, out_len);
    if (variable_rc <= 0) {
        return variable_rc;
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
