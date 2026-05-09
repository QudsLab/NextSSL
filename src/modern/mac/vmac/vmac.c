/* vmac.c — VMAC 64/128 implementation (Krovetz 2007, IETF draft-krovetz-vmac-01)
 *
 * This implements a simplified VMAC following the published specification.
 * VHASH operates on 128-bit chunks using NH (NH-based polynomial hashing)
 * followed by a Poly(2^61-1)-based polynomial evaluation.
 * The stream key is generated using AES-CTR.
 */
#include "vmac.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>

/* ── Constants ─────────────────────────────────────────────────────────── */
#define VMAC_NHBYTES   128u  /* NH processes 128-byte chunks */
#define P64  UINT64_C(0x1FFFFFFFFFFFFFFF)  /* 2^61 - 1 */

/* ── Helpers ───────────────────────────────────────────────────────────── */

static void aes_ecb(const uint8_t *key, size_t keylen,
                    const uint8_t in[16], uint8_t out[16])
{
    aes_ecb_encrypt_block(key, (int)(keylen * 8), in, out);
}

/* Load 64-bit little-endian */
static uint64_t load64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* Store 64-bit big-endian */
static void store64be(uint64_t v, uint8_t *p)
{
    for (int i = 7; i >= 0; i--) { p[i] = (uint8_t)(v & 0xFF); v >>= 8; }
}

/* 128-bit × 128-bit → 128-bit (lower) using 64-bit pieces */
static uint64_t mul64mod(uint64_t a, uint64_t b)
{
    /* multiply mod 2^64 (used in NH) */
    return a * b;
}

/* NH hash: process one 128-byte chunk with a 256-byte key stream
 * Returns a 128-bit value as two 64-bit words (lo, hi). */
static void nh_block(const uint8_t *msg, size_t msglen,
                     const uint64_t *k,
                     uint64_t *lo, uint64_t *hi)
{
    uint64_t s0 = 0, s1 = 0;
    size_t n = msglen / 8;
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint64_t m0, m1;
        memcpy(&m0, msg + i * 8,       8);
        memcpy(&m1, msg + (i+1) * 8,   8);
        s0 += mul64mod(m0 + k[i],   m1 + k[i+1]);
        s1 += mul64mod(m0 + k[i+2], m1 + k[i+3]);
    }
    *lo = s0;
    *hi = s1;
}

/* Derive VMAC stream key from AES key and nonce using AES-CTR */
static void vmac_derive_key(const uint8_t *key, size_t keylen,
                             const uint8_t nonce[16],
                             uint8_t stream[64])
{
    uint8_t ctr[16];
    memcpy(ctr, nonce, 16);
    for (int i = 0; i < 4; i++) {
        aes_ecb(key, keylen, ctr, stream + i * 16);
        /* Increment counter (last byte) */
        for (int j = 15; j >= 0; j--) {
            if (++ctr[j]) break;
        }
    }
}

/* Poly evaluation over GF(2^61-1) */
static uint64_t poly64(uint64_t *words, size_t n, uint64_t key)
{
    uint64_t y = 1;
    for (size_t i = 0; i < n; i++) {
        /* y = y * key + words[i]  mod P64 */
        __uint128_t t = (__uint128_t)y * key;
        uint64_t hi = (uint64_t)(t >> 64);
        uint64_t lo = (uint64_t)(t & 0xFFFFFFFFFFFFFFFFULL);
        y = lo + hi * (UINT64_C(1) << 3);  /* 2^61 ≡ 8 mod P64 */
        y = (y >> 61) ? (y & P64) + (y >> 61) : y;
        y += words[i];
        y = (y >= P64) ? y - P64 : y;
    }
    return y;
}

/* ── Public API ─────────────────────────────────────────────────────────── */

static int vmac_compute(const uint8_t *key,   size_t keylen,
                        const uint8_t  nonce[VMAC_NONCE_SIZE],
                        const uint8_t *msg,   size_t msglen,
                        int            tag128,
                        uint8_t       *tag)
{
    if (!key || !nonce || (!msg && msglen)) return -1;
    if (keylen != 16 && keylen != 24 && keylen != 32) return -1;

    /* Derive 64-byte stream = 8 × uint64_t NH sub-keys + 2 poly keys */
    uint8_t stream[64];
    vmac_derive_key(key, keylen, nonce, stream);
    uint64_t nh_key[8];
    for (int i = 0; i < 8; i++) memcpy(&nh_key[i], stream + i * 8, 8);

    /* Pad message to VMAC_NHBYTES boundary */
    size_t pad_len = msglen;
    if (pad_len % VMAC_NHBYTES != 0) pad_len += VMAC_NHBYTES - (pad_len % VMAC_NHBYTES);
    if (pad_len == 0) pad_len = VMAC_NHBYTES;

    uint8_t *padded = (uint8_t *)calloc(pad_len, 1);
    if (!padded) return -1;
    if (msglen) memcpy(padded, msg, msglen);

    /* NH-hash each chunk, collect poly words */
    size_t nchunks = pad_len / VMAC_NHBYTES;
    uint64_t *poly_words = (uint64_t *)calloc(nchunks, sizeof(uint64_t));
    if (!poly_words) { free(padded); return -1; }

    for (size_t i = 0; i < nchunks; i++) {
        uint64_t lo, hi;
        size_t chunk_len = (i == nchunks - 1 && msglen % VMAC_NHBYTES)
                           ? msglen % VMAC_NHBYTES : VMAC_NHBYTES;
        nh_block(padded + i * VMAC_NHBYTES, chunk_len, nh_key, &lo, &hi);
        poly_words[i] = lo ^ hi;
    }

    /* Include message bit-length as final word */
    uint64_t bit_len = (uint64_t)msglen * 8;

    uint64_t poly_key0 = load64le(stream) & P64;
    uint64_t h = poly64(poly_words, nchunks, poly_key0);
    h ^= bit_len;

    free(poly_words);
    free(padded);

    /* Final: encrypt nonce XOR h with AES to produce tag */
    uint8_t tmp[16];
    memcpy(tmp, nonce, 16);
    for (int i = 0; i < 8; i++) tmp[i] ^= (uint8_t)(h >> (i * 8));
    uint8_t out[16];
    aes_ecb(key, keylen, tmp, out);

    if (tag128) {
        memcpy(tag, out, 16);
    } else {
        memcpy(tag, out, 8);
    }
    return 0;
}

int vmac64(const uint8_t *key,   size_t keylen,
           const uint8_t  nonce[VMAC_NONCE_SIZE],
           const uint8_t *msg,   size_t msglen,
           uint8_t        tag[VMAC_TAG64_SIZE])
{
    return vmac_compute(key, keylen, nonce, msg, msglen, 0, tag);
}

int vmac128(const uint8_t *key,   size_t keylen,
            const uint8_t  nonce[VMAC_NONCE_SIZE],
            const uint8_t *msg,   size_t msglen,
            uint8_t        tag[VMAC_TAG128_SIZE])
{
    return vmac_compute(key, keylen, nonce, msg, msglen, 1, tag);
}
