/* dsa.c — Classical DSA (FIPS 186-4)
 *
 * This is a structural / stub implementation that provides the correct
 * API surface for the KAT harness.  Full big-integer arithmetic requires
 * a big-number library (e.g., WolfSSL's fp_int or a standalone BN).
 *
 * TODO: wire to a real BN backend (mp_int from wolfSSL or libtommath).
 *       Until then the sign/verify functions return -1 for non-trivial inputs.
 */
#include "dsa.h"
#include <stdlib.h>
#include <string.h>

/* Parameter set sizes in bits */
static const struct { int L; int N; } DSA_SIZES[] = {
    {1024, 160},
    {2048, 224},
    {2048, 256},
    {3072, 256}
};

struct dsa_params {
    dsa_params_id_t id;
    int L, N;
    uint8_t *p;   /* L/8 bytes */
    uint8_t *q;   /* N/8 bytes */
    uint8_t *g;   /* L/8 bytes */
};

struct dsa_key {
    const dsa_params_t *params;
    uint8_t *x;   /* N/8 bytes — private (may be NULL for public-only) */
    uint8_t *y;   /* L/8 bytes — public  */
};

dsa_params_t *dsa_params_generate(dsa_params_id_t id)
{
    if ((int)id < 0 || id > DSA_PARAMS_3072_256) return NULL;
    dsa_params_t *p = (dsa_params_t *)calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->id = id;
    p->L  = DSA_SIZES[id].L;
    p->N  = DSA_SIZES[id].N;
    /* Allocation placeholders; actual prime generation requires BN backend */
    p->p = (uint8_t *)calloc(1, (size_t)(p->L / 8));
    p->q = (uint8_t *)calloc(1, (size_t)(p->N / 8));
    p->g = (uint8_t *)calloc(1, (size_t)(p->L / 8));
    if (!p->p || !p->q || !p->g) { dsa_params_free(p); return NULL; }
    return p;
}

void dsa_params_free(dsa_params_t *params)
{
    if (!params) return;
    free(params->p); free(params->q); free(params->g);
    free(params);
}

dsa_key_t *dsa_keygen(const dsa_params_t *params)
{
    if (!params) return NULL;
    dsa_key_t *k = (dsa_key_t *)calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->params = params;
    k->x = (uint8_t *)calloc(1, (size_t)(params->N / 8));
    k->y = (uint8_t *)calloc(1, (size_t)(params->L / 8));
    if (!k->x || !k->y) { dsa_key_free(k); return NULL; }
    return k;
}

void dsa_key_free(dsa_key_t *key)
{
    if (!key) return;
    if (key->x) { memset(key->x, 0, (size_t)(key->params->N / 8)); free(key->x); }
    free(key->y);
    free(key);
}

int dsa_export_public(const dsa_key_t *key, uint8_t *buf, size_t buflen)
{
    if (!key || !buf) return -1;
    size_t need = (size_t)(key->params->L / 8);
    if (buflen < need) return -1;
    memcpy(buf, key->y, need);
    return 0;
}

int dsa_export_private(const dsa_key_t *key, uint8_t *buf, size_t buflen)
{
    if (!key || !key->x || !buf) return -1;
    size_t need = (size_t)(key->params->N / 8);
    if (buflen < need) return -1;
    memcpy(buf, key->x, need);
    return 0;
}

dsa_key_t *dsa_import_keypair(const dsa_params_t *params,
                               const uint8_t *x, size_t xlen,
                               const uint8_t *y, size_t ylen)
{
    if (!params || !x || !y) return NULL;
    size_t nlen = (size_t)(params->N / 8);
    size_t llen = (size_t)(params->L / 8);
    if (xlen != nlen || ylen != llen) return NULL;
    dsa_key_t *k = (dsa_key_t *)calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->params = params;
    k->x = (uint8_t *)malloc(nlen);
    k->y = (uint8_t *)malloc(llen);
    if (!k->x || !k->y) { dsa_key_free(k); return NULL; }
    memcpy(k->x, x, nlen);
    memcpy(k->y, y, llen);
    return k;
}

dsa_key_t *dsa_import_public(const dsa_params_t *params,
                              const uint8_t *y, size_t ylen)
{
    if (!params || !y) return NULL;
    size_t llen = (size_t)(params->L / 8);
    if (ylen != llen) return NULL;
    dsa_key_t *k = (dsa_key_t *)calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->params = params;
    k->y = (uint8_t *)malloc(llen);
    if (!k->y) { dsa_key_free(k); return NULL; }
    memcpy(k->y, y, llen);
    return k;
}

int dsa_sign(const dsa_key_t *key,
             const uint8_t *hash, size_t hash_len,
             uint8_t *r_out, uint8_t *s_out)
{
    (void)key; (void)hash; (void)hash_len; (void)r_out; (void)s_out;
    /* TODO: BN backend required */
    return -1;
}

int dsa_sign_k(const dsa_key_t *key,
               const uint8_t *hash, size_t hash_len,
               const uint8_t *k,    size_t k_len,
               uint8_t *r_out, uint8_t *s_out)
{
    (void)key; (void)hash; (void)hash_len; (void)k; (void)k_len;
    (void)r_out; (void)s_out;
    /* TODO: BN backend required */
    return -1;
}

int dsa_verify(const dsa_key_t *key,
               const uint8_t *hash, size_t hash_len,
               const uint8_t *r,    size_t r_len,
               const uint8_t *s,    size_t s_len)
{
    (void)key; (void)hash; (void)hash_len; (void)r; (void)r_len; (void)s; (void)s_len;
    /* TODO: BN backend required */
    return -1;
}
