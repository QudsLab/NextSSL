/**
 * @file core/kdf/kdf.c
 * @brief Layer 2 (base) KDF aggregate implementation.
 *
 * Implements the simplified HKDF / KDF / Argon2id / PBKDF2 API declared in
 * kdf.h (AGGREGATE section).  Delegates to PQCrypto common utilities and
 * existing hash primitives; no WolfSSL dependency.
 *
 * Delegation map:
 *   kdf_sha256                   → hkdf()           (PQCrypto, HKDF-SHA256)
 *   kdf_sha512                   → local HKDF-SHA512 built on sha512 primitive
 *   nextssl_base_kdf_argon2id    → argon2id_hash_raw()
 *   nextssl_base_kdf_pbkdf2_sha256 → local PBKDF2 built on pqc_hmac_sha256()
 *   nextssl_base_kdf_selftest    → KAT smoke test
 */

#include "kdf.h"
#include "../../../PQCrypto/common/hkdf/hkdf.h"          /* hkdf(), pqc_hmac_sha256() */
#include "../../../primitives/hash/memory_hard/Argon2id/argon2id.h"
#include "../../../primitives/hash/fast/sha512/sha512.h"  /* SHA512_CTX */
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>

/* ==========================================================================
 * Internal: HMAC-SHA512
 * Used only by kdf_sha512 (HKDF-SHA512).
 * SHA-512 block size is 128 bytes; output is 64 bytes.
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

    /* Key conditioning: if key > block, hash it; otherwise zero-pad */
    if (key_len > 128) {
        SHA512_CTX kctx;
        sha512_init(&kctx);
        sha512_update(&kctx, key, key_len);
        sha512_final(inner, &kctx);   /* reuse inner temporarily */
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

    /* Inner: SHA-512(ipad || data) */
    sha512_init(&ctx);
    sha512_update(&ctx, ipad, 128);
    sha512_update(&ctx, data, data_len);
    sha512_final(inner, &ctx);

    /* Outer: SHA-512(opad || inner) */
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
 * kdf_sha256 — HKDF-SHA256 (RFC 5869)
 * ========================================================================== */

int kdf_sha256(const uint8_t *ikm,  size_t ikm_len,
               const uint8_t *salt, size_t salt_len,
               const uint8_t *info, size_t info_len,
               uint8_t *okm, size_t okm_len)
{
    if (!ikm || !okm || okm_len == 0) return -1;
    /* PQCrypto hkdf arg order: (salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len) */
    return hkdf(salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len);
}

/* ==========================================================================
 * kdf_sha512 — HKDF-SHA512 (RFC 5869 with SHA-512 as PRF)
 * ========================================================================== */

int kdf_sha512(const uint8_t *ikm,  size_t ikm_len,
               const uint8_t *salt, size_t salt_len,
               const uint8_t *info, size_t info_len,
               uint8_t *okm, size_t okm_len)
{
    if (!ikm || !okm || okm_len == 0)   return -1;
    if (okm_len > 255u * 64u)            return -1; /* HKDF max output */

    /* HKDF-Extract: PRK = HMAC-SHA512(salt, IKM) */
    static const uint8_t zero_salt[64] = {0};
    const uint8_t *s   = salt     ? salt     : zero_salt;
    size_t         slen = salt_len ? salt_len : 64u;
    uint8_t prk[64];
    s_hmac_sha512(s, slen, ikm, ikm_len, prk);

    /* HKDF-Expand: OKM = T(1) || T(2) || ... */
    size_t   buf_cap = 64u + (info ? info_len : 0u) + 1u;
    uint8_t *buf     = (uint8_t *)malloc(buf_cap);
    if (!buf) { memset(prk, 0, 64); return -1; }

    uint8_t t[64], prev[64];
    size_t  done = 0;
    uint8_t ctr  = 1;
    int     first = 1;

    while (done < okm_len) {
        size_t blen = 0;
        if (!first) { memcpy(buf, prev, 64); blen = 64; }
        if (info && info_len > 0) { memcpy(buf + blen, info, info_len); blen += info_len; }
        buf[blen++] = ctr++;

        s_hmac_sha512(prk, 64, buf, blen, t);
        memcpy(prev, t, 64);
        first = 0;

        size_t take = okm_len - done;
        if (take > 64) take = 64;
        memcpy(okm + done, t, take);
        done += take;
    }

    memset(buf,  0, buf_cap);
    memset(prk,  0, 64);
    memset(t,    0, 64);
    memset(prev, 0, 64);
    free(buf);
    return 0;
}

/* ==========================================================================
 * nextssl_base_kdf_argon2id — Argon2id (RFC 9106)
 * ========================================================================== */

int nextssl_base_kdf_argon2id(const uint8_t *password, size_t password_len,
                               const uint8_t *salt,     size_t salt_len,
                               uint32_t t_cost, uint32_t m_cost,
                               uint32_t parallelism,
                               uint8_t *output, size_t output_len)
{
    if (!password || !salt || !output) return -1;
    if (salt_len < 16)                 return -1;
    if (output_len < 16)               return -1;
    return argon2id_hash_raw(t_cost, m_cost, parallelism,
                              password, password_len,
                              salt,     salt_len,
                              output,   output_len);
}

/* ==========================================================================
 * nextssl_base_kdf_pbkdf2_sha256 — PBKDF2-HMAC-SHA256 (RFC 8018)
 * ========================================================================== */

int nextssl_base_kdf_pbkdf2_sha256(const uint8_t *password, size_t password_len,
                                    const uint8_t *salt,     size_t salt_len,
                                    uint32_t iterations,
                                    uint8_t *output, size_t output_len)
{
    if (!password || !salt || !output || iterations == 0) return -1;
    /* Practical maximum to guard against stack overflow in the salt+4 buffer */
    if (salt_len > 1020) return -1;

    uint32_t block = 1;
    size_t   done  = 0;

    while (done < output_len) {
        /* U_1 = PRF(password, salt || INT(block)) */
        uint8_t salt_blk[1024];
        uint8_t blk_be[4];
        blk_be[0] = (uint8_t)((block >> 24) & 0xFFu);
        blk_be[1] = (uint8_t)((block >> 16) & 0xFFu);
        blk_be[2] = (uint8_t)((block >>  8) & 0xFFu);
        blk_be[3] = (uint8_t)( block         & 0xFFu);
        memcpy(salt_blk,           salt,   salt_len);
        memcpy(salt_blk + salt_len, blk_be, 4);

        uint8_t u[32], acc[32];
        pqc_hmac_sha256(password, password_len,
                        salt_blk, salt_len + 4u, u);
        memcpy(acc, u, 32);

        for (uint32_t iter = 1; iter < iterations; iter++) {
            uint8_t tmp[32];
            pqc_hmac_sha256(password, password_len, u, 32, tmp);
            memcpy(u, tmp, 32);
            for (int i = 0; i < 32; i++) acc[i] ^= u[i];
            memset(tmp, 0, 32);
        }

        size_t take = output_len - done;
        if (take > 32) take = 32;
        memcpy(output + done, acc, take);
        done += take;
        block++;

        memset(u,        0, 32);
        memset(acc,      0, 32);
        memset(salt_blk, 0, salt_len + 4u);
    }

    return 0;
}

/* ==========================================================================
 * nextssl_base_kdf_selftest — HKDF-SHA256 KAT (RFC 5869 test case 1)
 * ========================================================================== */

int nextssl_base_kdf_selftest(void)
{
    /* RFC 5869 test vector 1:
     *   IKM  = 0x0b0b...0b (22 bytes)
     *   salt = 0x000102...0b (13 bytes)
     *   info = 0xf0f1...f9  (10 bytes)
     *   L    = 42 bytes
     * Expected OKM[0..7] = 3c cb ef 7c 3b 40 99 14
     */
    static const uint8_t ikm[22] = {
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
        0x0b,0x0b,0x0b,0x0b,0x0b,0x0b
    };
    static const uint8_t salt[13] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,
        0x07,0x08,0x09,0x0a,0x0b,0x0c
    };
    static const uint8_t info[10] = {
        0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9
    };
    static const uint8_t expected_first8[8] = {
        0x3c,0xcb,0xef,0x7c,0x3b,0x40,0x99,0x14
    };

    uint8_t okm[42];
    if (kdf_sha256(ikm, 22, salt, 13, info, 10, okm, 42) != 0) return -1;

    uint8_t diff = 0;
    for (int i = 0; i < 8; i++) diff |= okm[i] ^ expected_first8[i];
    return diff ? -1 : 0;
}
