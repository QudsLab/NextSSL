/* marsupilami14.c — MarsupilamiFourteen (M14) hash function
 *
 * Identical tree structure to KangarooTwelve but uses:
 *   - TurboSHAKE256 (rate=136, 14 rounds) instead of TurboSHAKE128
 *   - Leaf digest length = 64 bytes
 *   - Default output = 64 bytes
 */
#include "marsupilami14.h"
#include <stdlib.h>
#include <string.h>

#define M14_DOMAIN_LEAF  0x0B
#define M14_DOMAIN_FINAL 0x06

static const uint8_t m14_suffix[8] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static size_t m14_right_encode(uint64_t x, uint8_t *buf)
{
    if (x == 0) { buf[0] = 0; buf[1] = 1; return 2; }
    uint8_t tmp[8]; size_t n = 0;
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    for (size_t i = 0; i < n; i++) buf[i] = tmp[n-1-i];
    buf[n] = (uint8_t)n;
    return n + 1;
}

int m14_init(M14_CTX *ctx, size_t outlen,
             const uint8_t *custom, size_t clen)
{
    (void)custom; (void)clen;  /* customization absorbed at final if needed */
    memset(ctx, 0, sizeof(*ctx));
    ctx->out_bytes = outlen > 0 ? outlen : 64;

    ctx->leaf_buf = (uint8_t *)malloc(M14_CHUNK_SIZE);
    if (!ctx->leaf_buf) return -1;

    /* TurboSHAKE256: rate=136, 14 rounds */
    turboshake_init(&ctx->node, 136, 14);
    ctx->initialized = 1;
    return 0;
}

void m14_update(M14_CTX *ctx, const uint8_t *data, size_t dlen)
{
    if (!ctx->initialized) return;

    size_t i = 0;
    while (i < dlen) {
        if (ctx->leaf_count == 0) {
            size_t room = M14_CHUNK_SIZE - ctx->leaf_pos;
            size_t copy = (dlen - i) < room ? (dlen - i) : room;
            turboshake_update(&ctx->node, data + i, copy);
            ctx->leaf_pos += copy;
            i += copy;
            if (ctx->leaf_pos == M14_CHUNK_SIZE) {
                turboshake_update(&ctx->node, m14_suffix, sizeof(m14_suffix));
                ctx->leaf_pos  = 0;
                ctx->leaf_count = 1;
                turboshake_init(&ctx->leaf, 136, 14);
            }
        } else {
            size_t room = M14_CHUNK_SIZE - ctx->leaf_pos;
            size_t copy = (dlen - i) < room ? (dlen - i) : room;
            memcpy(ctx->leaf_buf + ctx->leaf_pos, data + i, copy);
            ctx->leaf_pos += copy;
            i += copy;
            if (ctx->leaf_pos == M14_CHUNK_SIZE) {
                turboshake_update(&ctx->leaf, ctx->leaf_buf, M14_CHUNK_SIZE);
                uint8_t leaf_hash[M14_LEAF_LEN];
                TURBOSHAKE_CTX tmp = ctx->leaf;
                turboshake_final(&tmp, M14_DOMAIN_LEAF);
                turboshake_squeeze(&tmp, leaf_hash, M14_LEAF_LEN);
                uint8_t *na = (uint8_t *)realloc(ctx->node_acc,
                                                  ctx->node_acc_len + M14_LEAF_LEN);
                if (na) {
                    ctx->node_acc = na;
                    memcpy(ctx->node_acc + ctx->node_acc_len, leaf_hash, M14_LEAF_LEN);
                    ctx->node_acc_len += M14_LEAF_LEN;
                }
                ctx->leaf_count++;
                ctx->leaf_pos = 0;
                turboshake_init(&ctx->leaf, 136, 14);
            }
        }
    }
}

void m14_final(M14_CTX *ctx, uint8_t *out)
{
    if (!ctx->initialized) return;

    if (ctx->leaf_count == 0) {
        turboshake_final(&ctx->node, M14_DOMAIN_FINAL);
        turboshake_squeeze(&ctx->node, out, ctx->out_bytes);
        return;
    }

    if (ctx->leaf_pos > 0) {
        turboshake_update(&ctx->leaf, ctx->leaf_buf, ctx->leaf_pos);
        uint8_t leaf_hash[M14_LEAF_LEN];
        turboshake_final(&ctx->leaf, M14_DOMAIN_LEAF);
        turboshake_squeeze(&ctx->leaf, leaf_hash, M14_LEAF_LEN);
        uint8_t *na = (uint8_t *)realloc(ctx->node_acc,
                                          ctx->node_acc_len + M14_LEAF_LEN);
        if (na) {
            ctx->node_acc = na;
            memcpy(ctx->node_acc + ctx->node_acc_len, leaf_hash, M14_LEAF_LEN);
            ctx->node_acc_len += M14_LEAF_LEN;
        }
        ctx->leaf_count++;
    }

    if (ctx->node_acc && ctx->node_acc_len > 0)
        turboshake_update(&ctx->node, ctx->node_acc, ctx->node_acc_len);

    uint8_t renc[9];
    size_t  renc_len = m14_right_encode(ctx->leaf_count - 1, renc);
    turboshake_update(&ctx->node, renc, renc_len);

    static const uint8_t term[2] = {0xFF, 0xFF};
    turboshake_update(&ctx->node, term, 2);

    turboshake_final(&ctx->node, M14_DOMAIN_FINAL);
    turboshake_squeeze(&ctx->node, out, ctx->out_bytes);
}

void m14_destroy_fields(M14_CTX *ctx)
{
    if (ctx->leaf_buf) { free(ctx->leaf_buf); ctx->leaf_buf = NULL; }
    if (ctx->node_acc) { free(ctx->node_acc); ctx->node_acc = NULL; }
    ctx->initialized = 0;
}

int marsupilami14(const uint8_t *data,   size_t dlen,
                  const uint8_t *custom, size_t clen,
                  uint8_t *out, size_t outlen)
{
    if (!out || outlen == 0) return -1;
    M14_CTX ctx;
    if (m14_init(&ctx, outlen, custom, clen) != 0) return -1;
    m14_update(&ctx, data, dlen);
    m14_final(&ctx, out);
    m14_destroy_fields(&ctx);
    return 0;
}
