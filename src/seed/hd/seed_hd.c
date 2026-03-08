#include "seed_hd.h"
#include "../../primitives/hash/fast/sha512/sha512.h"
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Internal HMAC-SHA512
 * Built from the SHA-512 primitive — hkdf.h has no hmac_sha512 export.
 * key_len may exceed 64 bytes (pre-hashed per HMAC spec).
 * out must be 64 bytes.
 * ---------------------------------------------------------------------- */
static void hmac_sha512_internal(const uint8_t *key, size_t key_len,
                                 const uint8_t *data, size_t data_len,
                                 uint8_t        out[SHA512_DIGEST_LENGTH]) {
    uint8_t k_ipad[128];
    uint8_t k_opad[128];
    uint8_t k_real[SHA512_DIGEST_LENGTH];

    /* If key is longer than block size (128 bytes), hash it first */
    if (key_len > 128) {
        sha512_hash(key, key_len, k_real);
        key     = k_real;
        key_len = SHA512_DIGEST_LENGTH;
    }

    memset(k_ipad, 0x36, 128);
    memset(k_opad, 0x5c, 128);
    for (size_t i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    /* inner hash: H(k_ipad || data) */
    uint8_t inner[SHA512_DIGEST_LENGTH];
    SHA512_CTX ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, k_ipad, 128);
    sha512_update(&ctx, data, data_len);
    sha512_final(inner, &ctx);

    /* outer hash: H(k_opad || inner) */
    sha512_init(&ctx);
    sha512_update(&ctx, k_opad, 128);
    sha512_update(&ctx, inner, SHA512_DIGEST_LENGTH);
    sha512_final(out, &ctx);

    /* wipe intermediates */
    volatile uint8_t *wp = (volatile uint8_t *)inner;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) wp[i] = 0;
    wp = (volatile uint8_t *)k_ipad;
    for (int i = 0; i < 128; i++) wp[i] = 0;
    wp = (volatile uint8_t *)k_opad;
    for (int i = 0; i < 128; i++) wp[i] = 0;
}

/* -------------------------------------------------------------------------
 * seed_hd_master
 * ---------------------------------------------------------------------- */
int seed_hd_master(const uint8_t *master_seed, size_t seed_len,
                   uint8_t        master_key[32],
                   uint8_t        chain_code[32]) {
    if (!master_seed || seed_len < 16 || seed_len > 64) return -1;
    if (!master_key || !chain_code) return -1;

    static const uint8_t label[]  = "NextSSL seed";
    uint8_t digest[SHA512_DIGEST_LENGTH];

    hmac_sha512_internal(label, sizeof(label) - 1,
                         master_seed, seed_len,
                         digest);

    memcpy(master_key,  digest,      32);
    memcpy(chain_code,  digest + 32, 32);

    volatile uint8_t *wp = (volatile uint8_t *)digest;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) wp[i] = 0;

    return 0;
}

/* -------------------------------------------------------------------------
 * seed_hd_child
 * ---------------------------------------------------------------------- */
int seed_hd_child(const uint8_t *parent_key,
                  const uint8_t *chain_code,
                  uint32_t       index,
                  uint8_t        child_key[32],
                  uint8_t        child_chain[32]) {
    if (!parent_key || !chain_code || !child_key || !child_chain) return -1;

    /* data = 0x00 || parent_key[32] || BE32(index) for hardened;
             parent_key[32] || BE32(index)          for normal    */
    uint8_t data[37];
    size_t  dlen;

    uint8_t idx[4];
    idx[0] = (uint8_t)(index >> 24);
    idx[1] = (uint8_t)(index >> 16);
    idx[2] = (uint8_t)(index >>  8);
    idx[3] = (uint8_t)(index      );

    if (index & 0x80000000u) {
        /* hardened */
        data[0] = 0x00;
        memcpy(data + 1, parent_key, 32);
        memcpy(data + 33, idx, 4);
        dlen = 37;
    } else {
        /* normal */
        memcpy(data, parent_key, 32);
        memcpy(data + 32, idx, 4);
        dlen = 36;
    }

    uint8_t digest[SHA512_DIGEST_LENGTH];
    hmac_sha512_internal(chain_code, 32, data, dlen, digest);

    memcpy(child_key,   digest,      32);
    memcpy(child_chain, digest + 32, 32);

    volatile uint8_t *wp = (volatile uint8_t *)digest;
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) wp[i] = 0;
    wp = (volatile uint8_t *)data;
    for (size_t i = 0; i < dlen; i++) wp[i] = 0;

    return 0;
}

/* -------------------------------------------------------------------------
 * seed_hd_derive — parse path and walk the tree
 * ---------------------------------------------------------------------- */
int seed_hd_derive(const uint8_t *master_seed, size_t seed_len,
                   const char    *path,
                   uint8_t       *out,          size_t out_len) {
    if (!master_seed || !path || !out || out_len < 32) return -1;

    uint8_t key[32], chain[32];
    if (seed_hd_master(master_seed, seed_len, key, chain) != 0) return -1;

    /* Parse path: skip optional leading 'm' and '/' */
    const char *p = path;
    if (*p == 'm') p++;
    if (*p == '/') p++;

    while (*p != '\0') {
        /* Parse one decimal segment */
        char   *end;
        unsigned long seg = strtoul(p, &end, 10);
        if (end == p) break;               /* no digit — done */

        uint32_t index = (uint32_t)seg;
        if (*end == '\'') {
            index |= 0x80000000u;           /* hardened */
            end++;
        }
        if (*end == '/') end++;
        p = end;

        uint8_t ck[32], cc[32];
        if (seed_hd_child(key, chain, index, ck, cc) != 0) return -1;
        memcpy(key,   ck, 32);
        memcpy(chain, cc, 32);
    }

    memcpy(out, key, 32);

    /* wipe */
    volatile uint8_t *wp = (volatile uint8_t *)key;
    for (int i = 0; i < 32; i++) wp[i] = 0;
    wp = (volatile uint8_t *)chain;
    for (int i = 0; i < 32; i++) wp[i] = 0;

    return 0;
}
