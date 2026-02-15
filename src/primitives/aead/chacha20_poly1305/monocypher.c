#include "monocypher.h"
#include <string.h>

// ----------------------------------------------------------------------------
// Utils

static uint32_t load32_le(const uint8_t s[4]) {
    return (uint32_t)s[0] | ((uint32_t)s[1] << 8) | ((uint32_t)s[2] << 16) | ((uint32_t)s[3] << 24);
}

static void store32_le(uint8_t out[4], uint32_t in) {
    out[0] = in & 0xff;
    out[1] = (in >> 8) & 0xff;
    out[2] = (in >> 16) & 0xff;
    out[3] = (in >> 24) & 0xff;
}

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

void crypto_wipe(void *secret, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)secret;
    while (size--) *p++ = 0;
}

// ----------------------------------------------------------------------------
// ChaCha20

#define QROUND(a, b, c, d) \
    a += b; d = rotl32(d ^ a, 16); \
    c += d; b = rotl32(b ^ c, 12); \
    a += b; d = rotl32(d ^ a, 8); \
    c += d; b = rotl32(b ^ c, 7);

static void chacha20_block(uint32_t output[16], const uint32_t input[16]) {
    int i;
    uint32_t x[16];
    for (i = 0; i < 16; i++) x[i] = input[i];

    for (i = 0; i < 10; i++) {
        QROUND(x[0], x[4], x[8], x[12]);
        QROUND(x[1], x[5], x[9], x[13]);
        QROUND(x[2], x[6], x[10], x[14]);
        QROUND(x[3], x[7], x[11], x[15]);
        QROUND(x[0], x[5], x[10], x[15]);
        QROUND(x[1], x[6], x[11], x[12]);
        QROUND(x[2], x[7], x[8], x[13]);
        QROUND(x[3], x[4], x[9], x[14]);
    }

    for (i = 0; i < 16; i++) output[i] = x[i] + input[i];
}

static void chacha20_init_ietf(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) state[4 + i] = load32_le(key + i * 4);
    state[12] = counter;
    for (int i = 0; i < 3; i++) state[13 + i] = load32_le(nonce + i * 4);
}

static void chacha20_xor_stream(uint8_t *out, const uint8_t *in, size_t len, uint32_t state[16]) {
    uint32_t block[16];
    uint8_t stream[64];
    size_t i;

    while (len > 0) {
        chacha20_block(block, state);
        state[12]++; // Increment counter
        for (i = 0; i < 16; i++) store32_le(stream + i * 4, block[i]);

        size_t chunk = (len < 64) ? len : 64;
        for (i = 0; i < chunk; i++) out[i] = in[i] ^ stream[i];

        len -= chunk;
        in += chunk;
        out += chunk;
    }
    crypto_wipe(block, sizeof(block));
    crypto_wipe(stream, sizeof(stream));
}

// ----------------------------------------------------------------------------
// Poly1305

typedef struct {
    uint32_t r[5];
    uint32_t h[5];
    uint32_t pad[4];
    uint8_t buf[16];
    size_t buf_len;
} poly_ctx;

static void poly_init(poly_ctx *ctx, const uint8_t key[32]) {
    // R
    ctx->r[0] = load32_le(key) & 0x3ffffff;
    ctx->r[1] = (load32_le(key + 3) >> 2) & 0x3ffff03;
    ctx->r[2] = (load32_le(key + 6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (load32_le(key + 9) >> 6) & 0x3f03fff;
    ctx->r[4] = (load32_le(key + 12) >> 8) & 0x00fffff;
    
    // H
    for(int i=0; i<5; i++) ctx->h[i] = 0;
    
    // Pad (for finalization, though not used in standard accum)
    // Actually standard Poly1305 adds 's' at end.
    // Monocypher might handle this differently?
    // RFC 7539: Tag = (H + s) mod 2^128. s is second half of key.
    ctx->pad[0] = load32_le(key + 16);
    ctx->pad[1] = load32_le(key + 20);
    ctx->pad[2] = load32_le(key + 24);
    ctx->pad[3] = load32_le(key + 28);
    
    ctx->buf_len = 0;
}

static void poly_blocks(poly_ctx *ctx, const uint8_t *data, size_t len, int is_final) {
    // Simplified 26-bit implementation
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t r0 = ctx->r[0], r1 = ctx->r[1], r2 = ctx->r[2], r3 = ctx->r[3], r4 = ctx->r[4];
    uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;

    while (len >= 16) {
        // h += m
        h0 += load32_le(data) & 0x3ffffff;
        h1 += (load32_le(data + 3) >> 2) & 0x3ffffff;
        h2 += (load32_le(data + 6) >> 4) & 0x3ffffff;
        h3 += (load32_le(data + 9) >> 6) & 0x3ffffff;
        h4 += (load32_le(data + 12) >> 8) | (1 << 24);

        // h *= r
        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        // Reduce
        uint32_t c;
        h0 = (uint32_t)d0 & 0x3ffffff; c = (uint32_t)(d0 >> 26);
        d1 += c; h1 = (uint32_t)d1 & 0x3ffffff; c = (uint32_t)(d1 >> 26);
        d2 += c; h2 = (uint32_t)d2 & 0x3ffffff; c = (uint32_t)(d2 >> 26);
        d3 += c; h3 = (uint32_t)d3 & 0x3ffffff; c = (uint32_t)(d3 >> 26);
        d4 += c; h4 = (uint32_t)d4 & 0x3ffffff; c = (uint32_t)(d4 >> 26);
        h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
        h1 += c;

        data += 16;
        len -= 16;
    }
    
    ctx->h[0] = h0; ctx->h[1] = h1; ctx->h[2] = h2; ctx->h[3] = h3; ctx->h[4] = h4;
}

static void poly_update(poly_ctx *ctx, const uint8_t *data, size_t len) {
    if (len == 0) return;
    
    // Handle buffer
    if (ctx->buf_len > 0) {
        size_t needed = 16 - ctx->buf_len;
        if (len < needed) {
            memcpy(ctx->buf + ctx->buf_len, data, len);
            ctx->buf_len += len;
            return;
        }
        memcpy(ctx->buf + ctx->buf_len, data, needed);
        poly_blocks(ctx, ctx->buf, 16, 0);
        data += needed;
        len -= needed;
        ctx->buf_len = 0;
    }
    
    // Process full blocks
    size_t blocks_len = len & ~15;
    poly_blocks(ctx, data, blocks_len, 0);
    data += blocks_len;
    len -= blocks_len;
    
    // Buffer remaining
    if (len > 0) {
        memcpy(ctx->buf, data, len);
        ctx->buf_len = len;
    }
}

static void poly_final(poly_ctx *ctx, uint8_t mac[16]) {
    if (ctx->buf_len > 0) {
        ctx->buf[ctx->buf_len] = 1; // Pad with 1
        for (size_t i = ctx->buf_len + 1; i < 16; i++) ctx->buf[i] = 0;
        poly_blocks(ctx, ctx->buf, 16, 1);
    }
    
    // Final reduce
    uint32_t h0 = ctx->h[0], h1 = ctx->h[1], h2 = ctx->h[2], h3 = ctx->h[3], h4 = ctx->h[4];
    uint32_t c = h1 >> 26; h1 &= 0x3ffffff;
    h2 += c; c = h2 >> 26; h2 &= 0x3ffffff;
    h3 += c; c = h3 >> 26; h3 &= 0x3ffffff;
    h4 += c; c = h4 >> 26; h4 &= 0x3ffffff;
    h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff;
    h1 += c;
    
    // h mod 2^130 - 5
    uint32_t g0 = h0 + 5, g1 = h1, g2 = h2, g3 = h3, g4 = h4;
    c = g0 >> 26; g0 &= 0x3ffffff;
    g1 += c; c = g1 >> 26; g1 &= 0x3ffffff;
    g2 += c; c = g2 >> 26; g2 &= 0x3ffffff;
    g3 += c; c = g3 >> 26; g3 &= 0x3ffffff;
    g4 += c; c = g4 >> 26; g4 &= 0x3ffffff;
    
    // c is now 1 if h+5 >= 2^130 (meaning we should use g), else 0.
    uint32_t mask = 0 - c; 
    
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    // h = (h + pad) mod 2^128
    uint64_t f0 = (uint64_t)h0 + (h1 << 26) + (uint64_t)ctx->pad[0];
    uint64_t f1 = ((uint64_t)h1 >> 6) + (h2 << 20) + (uint64_t)ctx->pad[1] + (f0 >> 32);
    uint64_t f2 = ((uint64_t)h2 >> 12) + (h3 << 14) + (uint64_t)ctx->pad[2] + (f1 >> 32);
    uint64_t f3 = ((uint64_t)h3 >> 18) + (h4 << 8) + (uint64_t)ctx->pad[3] + (f2 >> 32);
    
    store32_le(mac, (uint32_t)f0);
    store32_le(mac + 4, (uint32_t)f1);
    store32_le(mac + 8, (uint32_t)f2);
    store32_le(mac + 12, (uint32_t)f3);
}

// ----------------------------------------------------------------------------
// AEAD

void crypto_aead_init_ietf(crypto_aead_ctx *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    memcpy(ctx->key, key, 32);
    // Store 12-byte nonce in counter+nonce fields
    // This is a HACK to fit IETF nonce into Monocypher's struct if strictly followed
    // But since we implement it, we define how we use it.
    // We'll store 4 bytes in counter (as part of nonce? no, counter is separate).
    // Wait, struct has: uint64_t counter; uint8_t key[32]; uint8_t nonce[8];
    // IETF requires 12 byte nonce.
    // We'll store the first 4 bytes of nonce in 'counter' (upper half?) and 8 in 'nonce'.
    // Or just overlay.
    // Let's assume the user doesn't access struct members directly for IETF.
    memcpy((uint8_t*)&ctx->counter, nonce, 4); // Store first 4 bytes
    memcpy(ctx->nonce, nonce + 4, 8);          // Store next 8 bytes
}

void crypto_aead_write(crypto_aead_ctx *ctx, uint8_t *cipher_text, uint8_t mac[16], 
                       const uint8_t *ad, size_t ad_size, const uint8_t *plain_text, size_t text_size) {
    uint32_t state[16];
    uint8_t one_time_key[32];
    uint8_t nonce[12];
    
    // Reconstruct nonce
    memcpy(nonce, (uint8_t*)&ctx->counter, 4);
    memcpy(nonce + 4, ctx->nonce, 8);
    
    // Generate Poly1305 key (counter 0)
    memset(one_time_key, 0, 32);
    chacha20_init_ietf(state, ctx->key, nonce, 0);
    chacha20_xor_stream(one_time_key, one_time_key, 32, state);

    // Encrypt plaintext (counter 1)
    chacha20_init_ietf(state, ctx->key, nonce, 1);
    chacha20_xor_stream(cipher_text, plain_text, text_size, state);
    
    // Poly1305
    poly_ctx pctx;
    poly_init(&pctx, one_time_key);
    poly_update(&pctx, ad, ad_size);
    if (ad_size % 16) {
        uint8_t pad[16] = {0};
        poly_update(&pctx, pad, 16 - (ad_size % 16));
    }
    poly_update(&pctx, cipher_text, text_size);
    if (text_size % 16) {
        uint8_t pad[16] = {0};
        poly_update(&pctx, pad, 16 - (text_size % 16));
    }
    uint8_t len_buf[16];
    store32_le(len_buf, (uint32_t)ad_size);
    store32_le(len_buf + 4, (uint32_t)(ad_size >> 32));
    store32_le(len_buf + 8, (uint32_t)text_size);
    store32_le(len_buf + 12, (uint32_t)(text_size >> 32));
    poly_update(&pctx, len_buf, 16);
    poly_final(&pctx, mac);
    
    crypto_wipe(&pctx, sizeof(pctx));
    crypto_wipe(one_time_key, sizeof(one_time_key));
    crypto_wipe(state, sizeof(state));
}

int crypto_aead_read(crypto_aead_ctx *ctx, uint8_t *plain_text, const uint8_t mac[16], 
                     const uint8_t *ad, size_t ad_size, const uint8_t *cipher_text, size_t text_size) {
    uint32_t state[16];
    uint8_t one_time_key[32];
    uint8_t calculated_mac[16];
    uint8_t nonce[12];
    
    // Reconstruct nonce
    memcpy(nonce, (uint8_t*)&ctx->counter, 4);
    memcpy(nonce + 4, ctx->nonce, 8);
    
    // Generate Poly1305 key (counter 0)
    memset(one_time_key, 0, 32);
    chacha20_init_ietf(state, ctx->key, nonce, 0);
    chacha20_xor_stream(one_time_key, one_time_key, 32, state);
    
    // Verify MAC
    poly_ctx pctx;
    poly_init(&pctx, one_time_key);
    poly_update(&pctx, ad, ad_size);
    if (ad_size % 16) {
        uint8_t pad[16] = {0};
        poly_update(&pctx, pad, 16 - (ad_size % 16));
    }
    poly_update(&pctx, cipher_text, text_size);
    if (text_size % 16) {
        uint8_t pad[16] = {0};
        poly_update(&pctx, pad, 16 - (text_size % 16));
    }
    uint8_t len_buf[16];
    store32_le(len_buf, (uint32_t)ad_size);
    store32_le(len_buf + 4, (uint32_t)(ad_size >> 32));
    store32_le(len_buf + 8, (uint32_t)text_size);
    store32_le(len_buf + 12, (uint32_t)(text_size >> 32));
    poly_update(&pctx, len_buf, 16);
    poly_final(&pctx, calculated_mac);
    
    crypto_wipe(&pctx, sizeof(pctx));
    crypto_wipe(one_time_key, sizeof(one_time_key));
    
    // Constant time compare
    int diff = 0;
    for (int i = 0; i < 16; i++) diff |= (calculated_mac[i] ^ mac[i]);
    
    if (diff != 0) {
        crypto_wipe(state, sizeof(state));
        return -1; // M_AUTHENTICATION_ERROR (usually -1 or non-zero)
    }
    
    // Decrypt (counter 1)
    chacha20_init_ietf(state, ctx->key, nonce, 1);
    chacha20_xor_stream(plain_text, cipher_text, text_size, state);
    
    crypto_wipe(state, sizeof(state));
    return 0;
}
