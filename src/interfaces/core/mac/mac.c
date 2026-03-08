/**
 * @file core/mac/mac.c
 * @brief Layer 2 (base) MAC aggregate implementation.
 *
 * Implements the simplified HMAC API declared in mac.h (AGGREGATE section).
 * Delegates to PQCrypto HMAC utilities and the sha512 primitive.
 *
 * Delegation map:
 *   mac_sha256 / mac_sha256_verify → pqc_hmac_sha256()  (PQCrypto, HMAC-SHA256)
 *   mac_sha512 / mac_sha512_verify → local HMAC-SHA512 on sha512 primitive
 *   mac_sha3_256 / mac_sha3_256_verify → hmac_sha3_256()  (PQCrypto)
 *   nextssl_base_mac_selftest      → constant-time HMAC-SHA256 KAT
 */

#include "mac.h"
#include "../../../PQCrypto/common/hkdf/hkdf.h"          /* pqc_hmac_sha256(), hmac_sha3_256() */
#include "../../../primitives/hash/fast/sha512/sha512.h"  /* SHA512_CTX */
#include <string.h>
#include <stdint.h>
#include <stddef.h>

/* ==========================================================================
 * Internal: HMAC-SHA512 (SHA-512 block size = 128 bytes)
 * ========================================================================== */

static void s_hmac_sha512(const uint8_t *key, size_t key_len,
                          const uint8_t *data, size_t data_len,
                          uint8_t out[64])
{
    uint8_t k[128];
    uint8_t ipad[128], opad[128];
    uint8_t inner[64];
    SHA512_CTX ctx;
    size_t i;

    if (key_len > 128) {
        SHA512_CTX kctx;
        sha512_init(&kctx);
        sha512_update(&kctx, key, key_len);
        sha512_final(inner, &kctx);
        memcpy(k, inner, 64);
        memset(k + 64, 0, 64);
    } else {
        memcpy(k, key, key_len);
        memset(k + key_len, 0, 128 - key_len);
    }

    for (i = 0; i < 128; i++) {
        ipad[i] = k[i] ^ 0x36u;
        opad[i] = k[i] ^ 0x5cu;
    }

    sha512_init(&ctx);
    sha512_update(&ctx, ipad, 128);
    sha512_update(&ctx, data, data_len);
    sha512_final(inner, &ctx);

    sha512_init(&ctx);
    sha512_update(&ctx, opad, 128);
    sha512_update(&ctx, inner, 64);
    sha512_final(out, &ctx);

    memset(k,     0, sizeof k);
    memset(ipad,  0, 128);
    memset(opad,  0, 128);
    memset(inner, 0, 64);
}

/* ==========================================================================
 * mac_sha256 / mac_sha256_verify — HMAC-SHA256
 * ========================================================================== */

int mac_sha256(const uint8_t *key,  size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t mac[32])
{
    if (!key || !data || !mac) return -1;
    pqc_hmac_sha256(key, key_len, data, data_len, mac);
    return 0;
}

int mac_sha256_verify(const uint8_t *key,          size_t key_len,
                      const uint8_t *data,         size_t data_len,
                      const uint8_t expected[32])
{
    if (!key || !data || !expected) return -1;
    uint8_t computed[32];
    pqc_hmac_sha256(key, key_len, data, data_len, computed);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ expected[i];
    memset(computed, 0, 32);
    return diff ? 0 : 1;
}

/* ==========================================================================
 * mac_sha512 / mac_sha512_verify — HMAC-SHA512
 * ========================================================================== */

int mac_sha512(const uint8_t *key,  size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t mac[64])
{
    if (!key || !data || !mac) return -1;
    s_hmac_sha512(key, key_len, data, data_len, mac);
    return 0;
}

int mac_sha512_verify(const uint8_t *key,          size_t key_len,
                      const uint8_t *data,         size_t data_len,
                      const uint8_t expected[64])
{
    if (!key || !data || !expected) return -1;
    uint8_t computed[64];
    s_hmac_sha512(key, key_len, data, data_len, computed);

    uint8_t diff = 0;
    for (int i = 0; i < 64; i++) diff |= computed[i] ^ expected[i];
    memset(computed, 0, 64);
    return diff ? 0 : 1;
}

/* ==========================================================================
 * mac_sha3_256 / mac_sha3_256_verify — HMAC-SHA3-256
 * ========================================================================== */

int mac_sha3_256(const uint8_t *key,  size_t key_len,
                 const uint8_t *data, size_t data_len,
                 uint8_t mac[32])
{
    if (!key || !data || !mac) return -1;
    hmac_sha3_256(key, key_len, data, data_len, mac);
    return 0;
}

int mac_sha3_256_verify(const uint8_t *key,          size_t key_len,
                        const uint8_t *data,         size_t data_len,
                        const uint8_t expected[32])
{
    if (!key || !data || !expected) return -1;
    uint8_t computed[32];
    hmac_sha3_256(key, key_len, data, data_len, computed);

    uint8_t diff = 0;
    for (int i = 0; i < 32; i++) diff |= computed[i] ^ expected[i];
    memset(computed, 0, 32);
    return diff ? 0 : 1;
}

/* ==========================================================================
 * nextssl_base_mac_selftest — HMAC-SHA256 KAT (RFC 2202 test case 1)
 * ========================================================================== */

int nextssl_base_mac_selftest(void)
{
    /* RFC 2202 test case 1:
     *   key  = 0x0b0b...0b (20 bytes)
     *   data = "Hi There"
     *   HMAC-SHA256[0..7] = b0344c 61d8 db38 535c a8af
     *   Expected first 4 bytes: b0 34 4c 61
     */
    static const uint8_t key[20] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t data[] = "Hi There";
    static const uint8_t expected4[4] = {0xb0, 0x34, 0x4c, 0x61};

    uint8_t mac[32];
    if (mac_sha256(key, 20, data, 8, mac) != 0) return -1;

    uint8_t diff = 0;
    for (int i = 0; i < 4; i++) diff |= mac[i] ^ expected4[i];
    return diff ? -1 : 0;
}
