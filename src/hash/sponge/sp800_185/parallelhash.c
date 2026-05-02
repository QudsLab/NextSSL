/* parallelhash.c — ParallelHash-128 and ParallelHash-256 (NIST SP 800-185 §6)
 * Single-threaded reference implementation. */
#include "parallelhash.h"
#include "cshake.h"
#include <stdlib.h>
#include <string.h>

/* ─── Inner block digest size in bytes (256 bits for both variants) ──── */
#define PH_INNER_BYTES 32u

/* SP 800-185 encoding primitives (local) */
static size_t ph_left_encode(uint64_t x, uint8_t *buf)
{
    uint8_t tmp[8];
    size_t n = 0;
    if (x == 0) { buf[0] = 1; buf[1] = 0; return 2; }
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    buf[0] = (uint8_t)n;
    for (size_t i = 0; i < n; i++) buf[1 + i] = tmp[n - 1 - i];
    return 1 + n;
}

static size_t ph_right_encode(uint64_t x, uint8_t *buf)
{
    uint8_t tmp[8];
    size_t n = 0;
    if (x == 0) { buf[0] = 0; buf[1] = 1; return 2; }
    uint64_t v = x;
    while (v) { tmp[n++] = (uint8_t)(v & 0xFF); v >>= 8; }
    for (size_t i = 0; i < n; i++) buf[i] = tmp[n - 1 - i];
    buf[n] = (uint8_t)n;
    return n + 1;
}

static const uint8_t N_parallelhash[] = {
    'P','a','r','a','l','l','e','l','H','a','s','h'
};

static int parallelhash_impl(int bits128,
                              const uint8_t *data, size_t datalen, size_t B,
                              const uint8_t *S, size_t Slen,
                              uint8_t *out, size_t outlen)
{
    if (B == 0 || !out || outlen == 0) return -1;

    /* n = max(ceil(datalen / B), 1) */
    size_t n = datalen == 0 ? 1 : (datalen + B - 1) / B;

    /* Allocate z = concat of n inner digests */
    uint8_t *z = (uint8_t *)malloc(n * PH_INNER_BYTES);
    if (!z) return -1;

    /* Hash each B-byte block with cSHAKE(block, 256, "", "") */
    for (size_t i = 0; i < n; i++) {
        const uint8_t *block = data + i * B;
        size_t block_len;
        if (datalen == 0) {
            block      = (const uint8_t *)"";
            block_len  = 0;
        } else {
            size_t start = i * B;
            size_t end   = start + B < datalen ? start + B : datalen;
            block_len    = end - start;
            block        = data + start;
        }
        /* Inner hash: cSHAKE(block, L, "", "") == SHAKE (N=S=empty → pure_shake) */
        {
            CSHAKE_CTX ictx;
            if (bits128)
                cshake128_init(&ictx, NULL, 0, NULL, 0);
            else
                cshake256_init(&ictx, NULL, 0, NULL, 0);
            cshake_update(&ictx, block, block_len);
            cshake_squeeze(&ictx, z + i * PH_INNER_BYTES, PH_INNER_BYTES);
        }
    }

    /* Build final message: left_encode(B) || z || right_encode(n) || right_encode(L) */
    CSHAKE_CTX ctx;
    if (bits128)
        cshake128_init(&ctx, N_parallelhash, sizeof(N_parallelhash), S, Slen);
    else
        cshake256_init(&ctx, N_parallelhash, sizeof(N_parallelhash), S, Slen);

    uint8_t enc[9];
    size_t enc_len;

    enc_len = ph_left_encode((uint64_t)B, enc);
    cshake_update(&ctx, enc, enc_len);

    cshake_update(&ctx, z, n * PH_INNER_BYTES);
    free(z);

    enc_len = ph_right_encode((uint64_t)n, enc);
    cshake_update(&ctx, enc, enc_len);

    enc_len = ph_right_encode((uint64_t)outlen * 8, enc);
    cshake_update(&ctx, enc, enc_len);

    cshake_squeeze(&ctx, out, outlen);
    return 0;
}

int parallelhash128(const uint8_t *data, size_t datalen, size_t B,
                    const uint8_t *S, size_t Slen,
                    uint8_t *out, size_t outlen)
{
    return parallelhash_impl(1, data, datalen, B, S, Slen, out, outlen);
}

int parallelhash256(const uint8_t *data, size_t datalen, size_t B,
                    const uint8_t *S, size_t Slen,
                    uint8_t *out, size_t outlen)
{
    return parallelhash_impl(0, data, datalen, B, S, Slen, out, outlen);
}
