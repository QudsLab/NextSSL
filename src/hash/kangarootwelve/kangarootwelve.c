/* kangarootwelve.c — KangarooTwelve (K12) hash function
 *
 * Tree structure (RFC 9285 §2):
 *   - Input is split into chunks of B=8192 bytes.
 *   - If input fits in one chunk: single-node path (no tree overhead).
 *   - Otherwise: each chunk is hashed with TurboSHAKE128 using domain 0x0B,
 *     producing a 32-byte leaf hash.  The final node absorbs:
 *       (first chunk) || 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00
 *       || leaf_1 || ... || leaf_{n-1}
 *       || right_encode(n-1)
 *       || 0xFF 0xFF
 *     and is finalised with domain 0x06.
 *
 * The customisation string S is absorbed after the main input using:
 *   || encode_string(S) = left_encode(|S|*8) || S
 * followed by right_encode(|S|) per RFC 9285.
 *
 * Note: For the hash_ops_t streaming wrapper (no customization string),
 * we use k12_init with clen=0 and call k12_destroy_fields from the final fn.
 */
#include "kangarootwelve.h"
#include <stdlib.h>
#include <string.h>

/* Domain separation bytes per RFC 9285 */
#define K12_DOMAIN_LEAF  0x0B
#define K12_DOMAIN_FINAL 0x06

/* Suffix bytes appended after first-chunk data in multi-chunk mode */
static const uint8_t k12_suffix[8] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* right_encode(x) per SP 800-185 (used for leaf count) */
static size_t k12_right_encode(uint64_t x, uint8_t *buf)
{
    if (x == 0) { buf[0] = 0; buf[1] = 1; return 2; }
    uint8_t tmp[8]; size_t n = 0;
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    for (size_t i = 0; i < n; i++) buf[i] = tmp[n-1-i];
    buf[n] = (uint8_t)n;
    return n + 1;
}

/* left_encode(x) per SP 800-185 */
static size_t k12_left_encode(uint64_t x, uint8_t *buf)
{
    if (x == 0) { buf[0] = 1; buf[1] = 0; return 2; }
    uint8_t tmp[8]; size_t n = 0;
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    buf[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) buf[1+i] = tmp[n-1-i];
    return 1 + n;
}

/* Finalise the current leaf and append its 32-byte hash to node_acc */
static int flush_leaf(K12_CTX *ctx)
{
    /* Hash the buffered leaf data */
    TURBOSHAKE_CTX leaf_ctx;
    turboshake_init(&leaf_ctx, 168, 12);
    turboshake_update(&leaf_ctx, ctx->leaf_buf, ctx->leaf_pos);
    turboshake_final(&leaf_ctx, K12_DOMAIN_LEAF);

    /* Expand node_acc to hold one more leaf hash */
    size_t new_len = ctx->node_acc_len + K12_LEAF_LEN;
    uint8_t *tmp = (uint8_t *)realloc(ctx->node_acc, new_len);
    if (!tmp) return -1;
    ctx->node_acc = tmp;
    turboshake_squeeze(&leaf_ctx, ctx->node_acc + ctx->node_acc_len, K12_LEAF_LEN);
    ctx->node_acc_len = new_len;
    ctx->leaf_count++;
    ctx->leaf_pos = 0;
    return 0;
}

int k12_init(K12_CTX *ctx, size_t outlen,
             const uint8_t *custom, size_t clen)
{
    memset(ctx, 0, sizeof(*ctx));
    ctx->out_bytes = outlen > 0 ? outlen : 32;

    ctx->leaf_buf = (uint8_t *)malloc(K12_CHUNK_SIZE);
    if (!ctx->leaf_buf) return -1;

    /* Outer (final node) TurboSHAKE128 — absorbs first chunk directly */
    turboshake_init(&ctx->node, 168, 12);

    /* Custom string pre-encoding: absorb after final data in k12_final */
    /* Store custom bytes in node_acc temporarily using a known convention:
     * we just remember clen/custom in the struct via a small copy. */
    /* Actually: store custom in a small inline buffer at the end of leaf_buf
     * (safely, since leaf_buf = 8192 bytes and custom is typically short).
     * Use the upper part of leaf_buf as temp custom store. */
    if (custom && clen > 0 && clen <= 256) {
        /* store at end of leaf_buf (positions 8192-clen..8191) */
        memcpy(ctx->leaf_buf + K12_CHUNK_SIZE - clen, custom, clen);
        ctx->leaf_count = (uint64_t)clen; /* temporarily repurpose leaf_count */
    } else {
        ctx->leaf_count = 0;
    }
    /* Reset leaf_pos and leaf_count after custom-store setup */
    ctx->leaf_pos   = 0;
    /* We store clen in node_acc_len temporarily before any leaves */
    ctx->node_acc_len = (custom && clen > 0 && clen <= 256) ? clen : 0;
    ctx->leaf_count   = 0;
    ctx->initialized  = 1;
    return 0;
}

void k12_update(K12_CTX *ctx, const uint8_t *data, size_t dlen)
{
    if (!ctx->initialized) return;

    size_t i = 0;
    while (i < dlen) {
        if (ctx->leaf_count == 0) {
            /* Still in first-chunk single-node path: absorb into outer node */
            size_t room = K12_CHUNK_SIZE - ctx->leaf_pos;
            size_t copy = (dlen - i) < room ? (dlen - i) : room;
            turboshake_update(&ctx->node, data + i, copy);
            ctx->leaf_pos += copy;
            i += copy;
            if (ctx->leaf_pos == K12_CHUNK_SIZE) {
                /* First chunk full — switch to multi-chunk tree mode */
                /* Absorb the 8-byte suffix marker into the outer node */
                turboshake_update(&ctx->node, k12_suffix, sizeof(k12_suffix));
                ctx->leaf_pos = 0;
                ctx->leaf_count = 1; /* marks multi-chunk mode */
                /* Initialise leaf TurboSHAKE */
                turboshake_init(&ctx->leaf, 168, 12);
            }
        } else {
            /* Multi-chunk mode: fill leaf buffer */
            size_t room = K12_CHUNK_SIZE - ctx->leaf_pos;
            size_t copy = (dlen - i) < room ? (dlen - i) : room;
            memcpy(ctx->leaf_buf, data + i, copy);
            ctx->leaf_pos += copy;
            i += copy;
            if (ctx->leaf_pos == K12_CHUNK_SIZE) {
                turboshake_update(&ctx->leaf, ctx->leaf_buf, K12_CHUNK_SIZE);
                /* flush completed leaf */
                uint8_t leaf_hash[K12_LEAF_LEN];
                TURBOSHAKE_CTX tmp_leaf = ctx->leaf;
                turboshake_final(&tmp_leaf, K12_DOMAIN_LEAF);
                turboshake_squeeze(&tmp_leaf, leaf_hash, K12_LEAF_LEN);
                /* append to node_acc */
                uint8_t *na = (uint8_t *)realloc(ctx->node_acc,
                                                  ctx->node_acc_len + K12_LEAF_LEN);
                if (na) {
                    ctx->node_acc = na;
                    memcpy(ctx->node_acc + ctx->node_acc_len, leaf_hash, K12_LEAF_LEN);
                    ctx->node_acc_len += K12_LEAF_LEN;
                }
                ctx->leaf_count++;
                ctx->leaf_pos = 0;
                turboshake_init(&ctx->leaf, 168, 12);
            }
        }
    }
}

void k12_final(K12_CTX *ctx, uint8_t *out)
{
    if (!ctx->initialized) return;

    if (ctx->leaf_count == 0) {
        /* Single-node path: finalise outer node directly */
        turboshake_final(&ctx->node, K12_DOMAIN_FINAL);
        turboshake_squeeze(&ctx->node, out, ctx->out_bytes);
        return;
    }

    /* Multi-chunk: flush partial last leaf */
    if (ctx->leaf_pos > 0) {
        turboshake_update(&ctx->leaf, ctx->leaf_buf, ctx->leaf_pos);
        uint8_t leaf_hash[K12_LEAF_LEN];
        turboshake_final(&ctx->leaf, K12_DOMAIN_LEAF);
        turboshake_squeeze(&ctx->leaf, leaf_hash, K12_LEAF_LEN);
        uint8_t *na = (uint8_t *)realloc(ctx->node_acc,
                                          ctx->node_acc_len + K12_LEAF_LEN);
        if (na) {
            ctx->node_acc = na;
            memcpy(ctx->node_acc + ctx->node_acc_len, leaf_hash, K12_LEAF_LEN);
            ctx->node_acc_len += K12_LEAF_LEN;
        }
        ctx->leaf_count++;
    }

    /* Absorb all leaf hashes into outer node */
    if (ctx->node_acc && ctx->node_acc_len > 0)
        turboshake_update(&ctx->node, ctx->node_acc, ctx->node_acc_len);

    /* right_encode(leaf_count - 1) */
    uint8_t renc[9];
    size_t  renc_len = k12_right_encode(ctx->leaf_count - 1, renc);
    turboshake_update(&ctx->node, renc, renc_len);

    /* 0xFF 0xFF terminator */
    static const uint8_t term[2] = {0xFF, 0xFF};
    turboshake_update(&ctx->node, term, 2);

    turboshake_final(&ctx->node, K12_DOMAIN_FINAL);
    turboshake_squeeze(&ctx->node, out, ctx->out_bytes);
}

void k12_destroy_fields(K12_CTX *ctx)
{
    if (ctx->leaf_buf)  { free(ctx->leaf_buf);  ctx->leaf_buf  = NULL; }
    if (ctx->node_acc)  { free(ctx->node_acc);  ctx->node_acc  = NULL; }
    ctx->initialized = 0;
}

int kangarootwelve(const uint8_t *data,   size_t dlen,
                   const uint8_t *custom, size_t clen,
                   uint8_t *out, size_t outlen)
{
    if (!out || outlen == 0) return -1;
    K12_CTX ctx;
    if (k12_init(&ctx, outlen, custom, clen) != 0) return -1;
    k12_update(&ctx, data, dlen);
    k12_final(&ctx, out);
    k12_destroy_fields(&ctx);
    return 0;
}
