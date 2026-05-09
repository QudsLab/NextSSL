/* umac.c — UMAC (RFC 4418)
 *
 * Implements RFC 4418 §4 UMAC-32/64/96/128.
 * Uses NH hashing and polynomial hash over GF(2^32-5) for 32-bit words.
 * AES-128 in counter mode generates the key material.
 *
 * Reference test vectors: RFC 4418 §7.
 */
#include "umac.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>
#include <stdlib.h>

/* ── Constants ─────────────────────────────────────────────────────────── */
#define UMAC_L1_KEY_LEN  1024u  /* 1024 bytes = 256 × 32-bit NH keys */
#define UMAC_BLOCK_LEN   1024u  /* L1 block size */
#define P32  UINT64_C(0xFFFFFFFB)  /* 2^32 - 5 */
#define P64  UINT64_C(0x1FFFFFFFFFFFFFFF)  /* 2^61 - 1 */

/* ── Helpers ───────────────────────────────────────────────────────────── */

static void aes_ecb(const uint8_t key[16], const uint8_t in[16], uint8_t out[16])
{
    aes_ecb_encrypt_block(key, 128, in, out);
}

static uint32_t load32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static void store32be(uint32_t v, uint8_t *p)
{
    p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)(v);
}

/* KDF: derive key stream bytes using AES-CTR starting at index */
static void kdf(const uint8_t master_key[16], uint8_t index,
                uint8_t *out, size_t outlen)
{
    uint8_t ctr[16] = {0};
    ctr[15] = index;
    size_t done = 0;
    uint8_t block[16];
    while (done < outlen) {
        aes_ecb(master_key, ctr, block);
        size_t take = outlen - done;
        if (take > 16) take = 16;
        memcpy(out + done, block, take);
        done += take;
        for (int i = 14; i >= 0; i--) if (++ctr[i]) break;
    }
}

/* NH-32: hash a 1024-byte (or shorter padded) block.
 * nh_key: 256 × uint32_t key words
 * msg:    padded message block (multiple of 32 bytes)
 * len:    actual message bytes (before padding)
 * Returns a 64-bit NH value. */
static uint64_t nh32(const uint32_t *nh_key, const uint8_t *msg,
                     size_t padded_len)
{
    size_t n = padded_len / 4;
    uint64_t sum = 0;
    for (size_t i = 0; i + 1 < n; i += 2) {
        uint32_t m0 = load32be(msg + i * 4);
        uint32_t m1 = load32be(msg + (i+1) * 4);
        sum += (uint64_t)(m0 + nh_key[i])   *
               (uint64_t)(m1 + nh_key[i+1]);
    }
    return sum;
}

/* Poly32: evaluate polynomial hash over GF(2^32-5) */
static uint64_t poly32(uint32_t k, const uint32_t *words, size_t n)
{
    uint64_t y = 1;
    for (size_t i = 0; i < n; i++) {
        y = ((y * k) % P32 + words[i]) % P32;
    }
    return y;
}

/* Inner UMAC computation for one tag component */
static int umac_component(const uint8_t key[16], int component,
                           const uint8_t *nonce, size_t nonce_len,
                           const uint8_t *msg, size_t msglen,
                           uint8_t tag[4])
{
    /* Derive NH key (1024 bytes) from master key */
    uint8_t nh_key_bytes[UMAC_L1_KEY_LEN];
    kdf(key, (uint8_t)(1 + component * 4), nh_key_bytes, UMAC_L1_KEY_LEN);
    uint32_t nh_key[256];
    for (int i = 0; i < 256; i++)
        nh_key[i] = load32be(nh_key_bytes + i * 4);

    /* Derive poly key: 8 bytes */
    uint8_t poly_key_bytes[8];
    kdf(key, (uint8_t)(2 + component * 4), poly_key_bytes, 8);
    uint32_t poly_k = load32be(poly_key_bytes) & (uint32_t)P32;

    /* Derive pad key: AES(nonce padded to 16 bytes) */
    uint8_t pad_key[16];
    kdf(key, (uint8_t)(3 + component * 4), pad_key, 16);

    /* Process message in UMAC_BLOCK_LEN chunks */
    size_t nblocks = (msglen + UMAC_BLOCK_LEN - 1) / UMAC_BLOCK_LEN;
    if (nblocks == 0) nblocks = 1;

    uint32_t *poly_words = (uint32_t *)calloc(nblocks, sizeof(uint32_t));
    if (!poly_words) return -1;

    for (size_t b = 0; b < nblocks; b++) {
        size_t off     = b * UMAC_BLOCK_LEN;
        size_t chunk   = msglen > off ? msglen - off : 0;
        if (chunk > UMAC_BLOCK_LEN) chunk = UMAC_BLOCK_LEN;

        /* Pad chunk to multiple of 32 bytes */
        size_t padlen = (chunk + 31) & ~(size_t)31;
        if (padlen == 0) padlen = 32;
        uint8_t buf[UMAC_BLOCK_LEN + 32] = {0};
        if (chunk) memcpy(buf, msg + off, chunk);

        uint64_t h = nh32(nh_key, buf, padlen);
        /* Add bit length of chunk */
        h += (uint64_t)chunk * 8;
        poly_words[b] = (uint32_t)(h % P32);
    }

    uint64_t poly_hash = poly32(poly_k, poly_words, nblocks);
    free(poly_words);

    /* Pad: AES-CTR stream at nonce */
    uint8_t nonce_padded[16] = {0};
    memcpy(nonce_padded, nonce, nonce_len < 16 ? nonce_len : 16);
    uint8_t pad_stream[16];
    aes_ecb(pad_key, nonce_padded, pad_stream);

    uint32_t pad32 = load32be(pad_stream + component * 4);
    uint32_t result = (uint32_t)(poly_hash & 0xFFFFFFFF) ^ pad32;
    store32be(result, tag);
    return 0;
}

int umac(const uint8_t  key[UMAC_KEY_SIZE],
         const uint8_t *nonce,   size_t nonce_len,
         const uint8_t *msg,     size_t msglen,
         uint8_t       *tag,     size_t tag_len)
{
    if (!key || !nonce || !nonce_len || !tag) return -1;
    int components;
    switch (tag_len) {
        case 4:  components = 1; break;
        case 8:  components = 2; break;
        case 12: components = 3; break;
        case 16: components = 4; break;
        default: return -1;
    }
    for (int c = 0; c < components; c++) {
        if (umac_component(key, c, nonce, nonce_len,
                           msg, msglen, tag + c * 4) != 0) return -1;
    }
    return 0;
}

int umac32(const uint8_t k[16], const uint8_t n[8], const uint8_t *m, size_t ml, uint8_t t[4])
{ return umac(k, n, 8, m, ml, t, 4); }
int umac64(const uint8_t k[16], const uint8_t n[8], const uint8_t *m, size_t ml, uint8_t t[8])
{ return umac(k, n, 8, m, ml, t, 8); }
int umac96(const uint8_t k[16], const uint8_t n[8], const uint8_t *m, size_t ml, uint8_t t[12])
{ return umac(k, n, 8, m, ml, t, 12); }
int umac128(const uint8_t k[16], const uint8_t n[8], const uint8_t *m, size_t ml, uint8_t t[16])
{ return umac(k, n, 8, m, ml, t, 16); }
