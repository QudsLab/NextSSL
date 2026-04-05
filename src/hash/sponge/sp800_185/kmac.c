/* kmac.c — KMAC-128 and KMAC-256 (NIST SP 800-185)
 *
 * cSHAKE construction:
 *   cSHAKE(X, L, N, S) = KECCAK[2L](bytepad(encode_string(N)||encode_string(S), w) || X || 00, L)
 * where padding byte is 0x04 (cSHAKE) instead of 0x1F (SHAKE).
 * When N="" and S="", reverts to SHAKE.
 *
 * KMAC(K, X, L, S) = cSHAKE(bytepad(encode_string(K), w) || X || right_encode(L), L, "KMAC", S)
 *
 * This file implements the encoding primitives and both keyed MAC and
 * unkeyed (hash_ops_t-compatible) modes.
 */
#include "kmac.h"
#include <string.h>

/* =========================================================================
 * SP 800-185 Integer and String Encoding Primitives
 * ========================================================================= */

/* left_encode(x) — minimum big-endian bytes for x, then byte count prefix.
 * Returns total bytes written to buf. buf must be >= 9 bytes. */
static size_t left_encode(uint64_t x, uint8_t *buf) {
    uint8_t tmp[8];
    size_t n = 0;
    if (x == 0) {
        buf[0] = 1;
        buf[1] = 0;
        return 2;
    }
    uint64_t v = x;
    while (v > 0) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    buf[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) buf[1 + i] = tmp[n - 1 - i]; /* big-endian */
    return 1 + n;
}

/* right_encode(x) — same layout as left_encode but count byte is appended.
 * Returns total bytes written. buf must be >= 9 bytes. */
static size_t right_encode(uint64_t x, uint8_t *buf) {
    uint8_t tmp[8];
    size_t n = 0;
    if (x == 0) {
        buf[0] = 0;
        buf[1] = 1;
        return 2;
    }
    uint64_t v = x;
    while (v > 0) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    for (size_t i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    buf[n] = (uint8_t)n;
    return n + 1;
}

/* encode_string(S) = left_encode(|S| in bits) || S
 * Absorbs the encoding directly into the SHAKE context. */
static void absorb_encode_string(SHAKE_CTX *shake,
                                 const uint8_t *s, size_t slen) {
    uint8_t enc[9];
    size_t enc_len = left_encode((uint64_t)slen * 8, enc);
    shake_update(shake, enc, enc_len);
    if (slen > 0) shake_update(shake, s, slen);
}

/* bytepad(X_bytes_in_shake, w) — after absorbing content into shake,
 * pad to next multiple of w by absorbing zeros.
 * This function is called AFTER the content has already been absorbed.
 * absorbed_so_far = number of bytes absorbed for the bytepad content
 * (including the initial left_encode(w) bytes). */
static void finish_bytepad(SHAKE_CTX *shake, size_t w, size_t absorbed_so_far) {
    size_t pad = w - (absorbed_so_far % w);
    if (pad == w) return; /* already aligned */
    static const uint8_t zeros[200] = {0};
    while (pad > 0) {
        size_t chunk = pad < sizeof(zeros) ? pad : sizeof(zeros);
        shake_update(shake, zeros, chunk);
        pad -= chunk;
    }
}

/* =========================================================================
 * Internal: initialise a cSHAKE sponge with N="KMAC", S=custom,
 * then absorb bytepad(encode_string(key), w) for the given key.
 * rate = 168 for KMAC-128, 136 for KMAC-256.
 * out_bytes: fixed output length stored in ctx.
 * ========================================================================= */
static void kmac_init_common(KMAC_CTX *ctx, size_t rate,
                              const uint8_t *key,    size_t klen,
                              const uint8_t *custom, size_t clen,
                              size_t out_bytes) {
    /* initialise underlying SHAKE sponge */
    memset(ctx->shake.state, 0, sizeof(ctx->shake.state));
    ctx->shake.rate      = rate;
    ctx->shake.buf_len   = 0;
    ctx->shake.finalized = 0;
    ctx->out_bytes       = out_bytes;

    /* --- bytepad(encode_string("KMAC") || encode_string(S), rate) --- */

    /* Start with left_encode(rate) */
    uint8_t w_enc[9];
    size_t  w_enc_len = left_encode((uint64_t)rate, w_enc);
    shake_update(&ctx->shake, w_enc, w_enc_len);
    size_t absorbed = w_enc_len;

    /* encode_string("KMAC") — N = function name bytes */
    static const uint8_t N_kmac[] = {'K','M','A','C'};
    uint8_t n_len_enc[9];
    size_t  n_len_enc_len = left_encode((uint64_t)sizeof(N_kmac) * 8, n_len_enc);
    shake_update(&ctx->shake, n_len_enc, n_len_enc_len);
    shake_update(&ctx->shake, N_kmac, sizeof(N_kmac));
    absorbed += n_len_enc_len + sizeof(N_kmac);

    /* encode_string(S) — customization string */
    absorb_encode_string(&ctx->shake, custom, clen);
    uint8_t clen_enc[9];
    size_t  clen_enc_len = left_encode((uint64_t)clen * 8, clen_enc);
    absorbed += clen_enc_len + clen;

    /* zero-pad to multiple of rate */
    finish_bytepad(&ctx->shake, rate, absorbed);

    /* --- bytepad(encode_string(K), rate) --- */
    uint8_t w_enc2[9];
    size_t  w_enc2_len = left_encode((uint64_t)rate, w_enc2);
    shake_update(&ctx->shake, w_enc2, w_enc2_len);
    size_t key_absorbed = w_enc2_len;

    /* encode_string(key) */
    uint8_t klen_enc[9];
    size_t  klen_enc_len = left_encode((uint64_t)klen * 8, klen_enc);
    shake_update(&ctx->shake, klen_enc, klen_enc_len);
    if (key && klen > 0) shake_update(&ctx->shake, key, klen);
    key_absorbed += klen_enc_len + klen;

    finish_bytepad(&ctx->shake, rate, key_absorbed);
}

/* =========================================================================
 * Streaming API
 * ========================================================================= */

void kmac128_init(KMAC_CTX *ctx,
                  const uint8_t *key,    size_t klen,
                  const uint8_t *custom, size_t clen) {
    kmac_init_common(ctx, 168, key, klen, custom, clen, 32);
}

void kmac256_init(KMAC_CTX *ctx,
                  const uint8_t *key,    size_t klen,
                  const uint8_t *custom, size_t clen) {
    kmac_init_common(ctx, 136, key, klen, custom, clen, 64);
}

void kmac_update(KMAC_CTX *ctx, const uint8_t *data, size_t dlen) {
    shake_update(&ctx->shake, data, dlen);
}

void kmac_final(KMAC_CTX *ctx, uint8_t *out) {
    /* append right_encode(out_bytes * 8) — output length in bits */
    uint8_t r_enc[9];
    size_t  r_enc_len = right_encode((uint64_t)ctx->out_bytes * 8, r_enc);
    shake_update(&ctx->shake, r_enc, r_enc_len);

    /* cSHAKE finalisation: 0x04 padding byte (not 0x1F like SHAKE) */
    shake_custom_final(&ctx->shake, 0x04);
    shake_squeeze(&ctx->shake, out, ctx->out_bytes);
}

/* =========================================================================
 * One-shot keyed KMAC
 * ========================================================================= */

int kmac128_compute(const uint8_t *key,    size_t klen,
                    const uint8_t *data,   size_t dlen,
                    const uint8_t *custom, size_t clen,
                    uint8_t *out, size_t outlen) {
    if (!key || !data || !out || outlen == 0) return -1;
    KMAC_CTX ctx;
    kmac_init_common(&ctx, 168, key, klen, custom, clen, outlen);
    shake_update(&ctx.shake, data, dlen);
    uint8_t r_enc[9];
    size_t  r_enc_len = right_encode((uint64_t)outlen * 8, r_enc);
    shake_update(&ctx.shake, r_enc, r_enc_len);
    shake_custom_final(&ctx.shake, 0x04);
    shake_squeeze(&ctx.shake, out, outlen);
    return 0;
}

int kmac256_compute(const uint8_t *key,    size_t klen,
                    const uint8_t *data,   size_t dlen,
                    const uint8_t *custom, size_t clen,
                    uint8_t *out, size_t outlen) {
    if (!key || !data || !out || outlen == 0) return -1;
    KMAC_CTX ctx;
    kmac_init_common(&ctx, 136, key, klen, custom, clen, outlen);
    shake_update(&ctx.shake, data, dlen);
    uint8_t r_enc[9];
    size_t  r_enc_len = right_encode((uint64_t)outlen * 8, r_enc);
    shake_update(&ctx.shake, r_enc, r_enc_len);
    shake_custom_final(&ctx.shake, 0x04);
    shake_squeeze(&ctx.shake, out, outlen);
    return 0;
}

/* =========================================================================
 * hash_ops_t-compatible unkeyed init helpers
 * (empty key K="", empty customization S="")
 * ========================================================================= */

void kmac128_ops_init_fn(KMAC_CTX *ctx) {
    kmac_init_common(ctx, 168, NULL, 0, NULL, 0, 32);
}

void kmac256_ops_init_fn(KMAC_CTX *ctx) {
    kmac_init_common(ctx, 136, NULL, 0, NULL, 0, 64);
}
