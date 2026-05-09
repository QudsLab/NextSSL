/* dh.c — Finite-field Diffie-Hellman (RFC 3526)
 *
 * Stub implementation — requires a bignum backend.
 * TODO: Wire to libtommath or WolfSSL wolfmath.
 *       Reference: examples/c/dh/
 */
#include "dh.h"
#include <stdlib.h>
#include <string.h>

/* RFC 3526 group sizes in bits */
static const struct { int bits; } DH_GROUPS[] = {
    [DH_GROUP_2048] = {2048},
    [DH_GROUP_3072] = {3072},
    [DH_GROUP_4096] = {4096}
};

struct dh_ctx {
    dh_group_t group;
    int bits;
};

size_t dh_private_key_size(dh_group_t group)
{
    /* Private exponent: 256 bits (32 bytes) for all groups per SP 800-56A */
    (void)group;
    return 32;
}

size_t dh_public_key_size(dh_group_t group)
{
    switch (group) {
        case DH_GROUP_2048: return 256;
        case DH_GROUP_3072: return 384;
        case DH_GROUP_4096: return 512;
    }
    return 0;
}

dh_ctx_t *dh_ctx_new(dh_group_t group)
{
    if (group != DH_GROUP_2048 && group != DH_GROUP_3072 && group != DH_GROUP_4096)
        return NULL;
    dh_ctx_t *ctx = (dh_ctx_t *)calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->group = group;
    ctx->bits  = DH_GROUPS[group].bits;
    return ctx;
}

void dh_ctx_free(dh_ctx_t *ctx) { free(ctx); }

int dh_keygen(dh_ctx_t *ctx,
              uint8_t *private_key,
              uint8_t *public_key)
{
    if (!ctx || !private_key || !public_key) return -1;
    /* TODO: Implement modular exponentiation via bignum backend.
     *       private = random exponent; public = g^private mod p */
    return -1;
}

int dh_shared_secret(dh_ctx_t       *ctx,
                     const uint8_t  *private_key,
                     const uint8_t  *their_public,
                     uint8_t        *shared,
                     size_t         *shared_len)
{
    if (!ctx || !private_key || !their_public || !shared || !shared_len) return -1;
    /* TODO: shared = their_public^private mod p via bignum backend */
    return -1;
}
