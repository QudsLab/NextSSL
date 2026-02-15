#include "hkdf.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include "../sha2.h"
#include "../fips202.h"

#define SHA256_HASH_SIZE 32
#define SHA3_256_HASH_SIZE 32
#define SHA3_512_HASH_SIZE 64

/* ========================================================================== */
/* HMAC-SHA256 (Renamed to avoid conflict)                                    */
/* ========================================================================== */

void pqc_hmac_sha256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out) {
    uint8_t ipad[64], opad[64];
    uint8_t hash_inner[SHA256_HASH_SIZE];
    size_t i;

    if (key_len > 64) {
        sha256(ipad, key, key_len);
        key = ipad;
        key_len = SHA256_HASH_SIZE;
    }

    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);

    for (i = 0; i < key_len; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    {
        sha256ctx ctx;
        sha256_inc_init(&ctx);
        sha256_inc_blocks(&ctx, ipad, 1);
        sha256_inc_finalize(hash_inner, &ctx, data, data_len);
    }

    {
        sha256ctx ctx;
        sha256_inc_init(&ctx);
        sha256_inc_blocks(&ctx, opad, 1);
        sha256_inc_finalize(out, &ctx, hash_inner, SHA256_HASH_SIZE);
    }
}

int hkdf_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk) {
    uint8_t null_salt[SHA256_HASH_SIZE] = {0};
    if (!salt) {
        salt = null_salt;
        salt_len = SHA256_HASH_SIZE;
    }
    pqc_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    return 0;
}

int hkdf_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t T[SHA256_HASH_SIZE];
    uint8_t counter = 1;
    size_t n = (okm_len + SHA256_HASH_SIZE - 1) / SHA256_HASH_SIZE;
    size_t i;

    if (n > 255) return -1;

    for (i = 0; i < n; i++) {
        uint8_t buffer[SHA256_HASH_SIZE + 256 + 1];
        size_t len = 0;
        
        if (i > 0) {
            memcpy(buffer + len, T, SHA256_HASH_SIZE);
            len += SHA256_HASH_SIZE;
        }
        
        if (info && info_len > 0) {
             if (len + info_len > sizeof(buffer) - 1) return -2; 
             memcpy(buffer + len, info, info_len);
             len += info_len;
        }
        
        buffer[len++] = counter++;
        
        uint8_t tmp_out[SHA256_HASH_SIZE];
        pqc_hmac_sha256(prk, prk_len, buffer, len, tmp_out);
        
        size_t to_copy = (okm_len - (i * SHA256_HASH_SIZE)) > SHA256_HASH_SIZE ? SHA256_HASH_SIZE : (okm_len - (i * SHA256_HASH_SIZE));
        memcpy(okm + i * SHA256_HASH_SIZE, tmp_out, to_copy);
        
        memcpy(T, tmp_out, SHA256_HASH_SIZE);
    }
    return 0;
}

int hkdf(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t prk[SHA256_HASH_SIZE];
    hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    return hkdf_expand(prk, SHA256_HASH_SIZE, info, info_len, okm, okm_len);
}

/* ========================================================================== */
/* HMAC-SHA3-256                                                              */
/* ========================================================================== */

void hmac_sha3_256(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out) {
    /* SHA3-256 block size (rate) is 136 bytes */
    #define SHA3_256_BLOCK_SIZE 136
    uint8_t ipad[SHA3_256_BLOCK_SIZE], opad[SHA3_256_BLOCK_SIZE];
    uint8_t hash_inner[SHA3_256_HASH_SIZE];
    uint8_t key_buf[SHA3_256_HASH_SIZE];
    size_t i;

    if (key_len > SHA3_256_BLOCK_SIZE) {
        sha3_256(key_buf, key, key_len);
        key = key_buf;
        key_len = SHA3_256_HASH_SIZE;
    }

    memset(ipad, 0x36, SHA3_256_BLOCK_SIZE);
    memset(opad, 0x5c, SHA3_256_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    /* Inner hash */
    {
        sha3_256incctx ctx;
        sha3_256_inc_init(&ctx);
        sha3_256_inc_absorb(&ctx, ipad, SHA3_256_BLOCK_SIZE);
        sha3_256_inc_absorb(&ctx, data, data_len);
        sha3_256_inc_finalize(hash_inner, &ctx);
    }

    /* Outer hash */
    {
        sha3_256incctx ctx;
        sha3_256_inc_init(&ctx);
        sha3_256_inc_absorb(&ctx, opad, SHA3_256_BLOCK_SIZE);
        sha3_256_inc_absorb(&ctx, hash_inner, SHA3_256_HASH_SIZE);
        sha3_256_inc_finalize(out, &ctx);
    }
}

int hkdf_sha3_256_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk) {
    uint8_t null_salt[SHA3_256_HASH_SIZE] = {0};
    if (!salt) {
        salt = null_salt;
        salt_len = SHA3_256_HASH_SIZE;
    }
    hmac_sha3_256(salt, salt_len, ikm, ikm_len, prk);
    return 0;
}

int hkdf_sha3_256_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t T[SHA3_256_HASH_SIZE];
    uint8_t counter = 1;
    size_t n = (okm_len + SHA3_256_HASH_SIZE - 1) / SHA3_256_HASH_SIZE;
    size_t i;

    if (n > 255) return -1;

    for (i = 0; i < n; i++) {
        uint8_t buffer[SHA3_256_HASH_SIZE + 256 + 1];
        size_t len = 0;
        
        if (i > 0) {
            memcpy(buffer + len, T, SHA3_256_HASH_SIZE);
            len += SHA3_256_HASH_SIZE;
        }
        
        if (info && info_len > 0) {
             if (len + info_len > sizeof(buffer) - 1) return -2; 
             memcpy(buffer + len, info, info_len);
             len += info_len;
        }
        
        buffer[len++] = counter++;
        
        uint8_t tmp_out[SHA3_256_HASH_SIZE];
        hmac_sha3_256(prk, prk_len, buffer, len, tmp_out);
        
        size_t to_copy = (okm_len - (i * SHA3_256_HASH_SIZE)) > SHA3_256_HASH_SIZE ? SHA3_256_HASH_SIZE : (okm_len - (i * SHA3_256_HASH_SIZE));
        memcpy(okm + i * SHA3_256_HASH_SIZE, tmp_out, to_copy);
        
        memcpy(T, tmp_out, SHA3_256_HASH_SIZE);
    }
    return 0;
}

int hkdf_sha3_256(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t prk[SHA3_256_HASH_SIZE];
    hkdf_sha3_256_extract(salt, salt_len, ikm, ikm_len, prk);
    return hkdf_sha3_256_expand(prk, SHA3_256_HASH_SIZE, info, info_len, okm, okm_len);
}

/* ========================================================================== */
/* HMAC-SHA3-512                                                              */
/* ========================================================================== */

void hmac_sha3_512(const uint8_t *key, size_t key_len, const uint8_t *data, size_t data_len, uint8_t *out) {
    /* SHA3-512 block size (rate) is 72 bytes */
    #define SHA3_512_BLOCK_SIZE 72
    uint8_t ipad[SHA3_512_BLOCK_SIZE], opad[SHA3_512_BLOCK_SIZE];
    uint8_t hash_inner[SHA3_512_HASH_SIZE];
    uint8_t key_buf[SHA3_512_HASH_SIZE];
    size_t i;

    if (key_len > SHA3_512_BLOCK_SIZE) {
        sha3_512(key_buf, key, key_len);
        key = key_buf;
        key_len = SHA3_512_HASH_SIZE;
    }

    memset(ipad, 0x36, SHA3_512_BLOCK_SIZE);
    memset(opad, 0x5c, SHA3_512_BLOCK_SIZE);

    for (i = 0; i < key_len; i++) {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }

    /* Inner hash */
    {
        sha3_512incctx ctx;
        sha3_512_inc_init(&ctx);
        sha3_512_inc_absorb(&ctx, ipad, SHA3_512_BLOCK_SIZE);
        sha3_512_inc_absorb(&ctx, data, data_len);
        sha3_512_inc_finalize(hash_inner, &ctx);
    }

    /* Outer hash */
    {
        sha3_512incctx ctx;
        sha3_512_inc_init(&ctx);
        sha3_512_inc_absorb(&ctx, opad, SHA3_512_BLOCK_SIZE);
        sha3_512_inc_absorb(&ctx, hash_inner, SHA3_512_HASH_SIZE);
        sha3_512_inc_finalize(out, &ctx);
    }
}

int hkdf_sha3_512_extract(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, uint8_t *prk) {
    uint8_t null_salt[SHA3_512_HASH_SIZE] = {0};
    if (!salt) {
        salt = null_salt;
        salt_len = SHA3_512_HASH_SIZE;
    }
    hmac_sha3_512(salt, salt_len, ikm, ikm_len, prk);
    return 0;
}

int hkdf_sha3_512_expand(const uint8_t *prk, size_t prk_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t T[SHA3_512_HASH_SIZE];
    uint8_t counter = 1;
    size_t n = (okm_len + SHA3_512_HASH_SIZE - 1) / SHA3_512_HASH_SIZE;
    size_t i;

    if (n > 255) return -1;

    for (i = 0; i < n; i++) {
        uint8_t buffer[SHA3_512_HASH_SIZE + 256 + 1];
        size_t len = 0;
        
        if (i > 0) {
            memcpy(buffer + len, T, SHA3_512_HASH_SIZE);
            len += SHA3_512_HASH_SIZE;
        }
        
        if (info && info_len > 0) {
             if (len + info_len > sizeof(buffer) - 1) return -2; 
             memcpy(buffer + len, info, info_len);
             len += info_len;
        }
        
        buffer[len++] = counter++;
        
        uint8_t tmp_out[SHA3_512_HASH_SIZE];
        hmac_sha3_512(prk, prk_len, buffer, len, tmp_out);
        
        size_t to_copy = (okm_len - (i * SHA3_512_HASH_SIZE)) > SHA3_512_HASH_SIZE ? SHA3_512_HASH_SIZE : (okm_len - (i * SHA3_512_HASH_SIZE));
        memcpy(okm + i * SHA3_512_HASH_SIZE, tmp_out, to_copy);
        
        memcpy(T, tmp_out, SHA3_512_HASH_SIZE);
    }
    return 0;
}

int hkdf_sha3_512(const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    uint8_t prk[SHA3_512_HASH_SIZE];
    hkdf_sha3_512_extract(salt, salt_len, ikm, ikm_len, prk);
    return hkdf_sha3_512_expand(prk, SHA3_512_HASH_SIZE, info, info_len, okm, okm_len);
}

/* ========================================================================== */
/* HKDF-Expand-Label (RFC 8446)                                               */
/* ========================================================================== */

int hkdf_expand_label(const uint8_t *secret, size_t secret_len, const char *label, const uint8_t *context, size_t context_len, uint8_t *okm, size_t okm_len) {
    /* 
     * struct {
     *     uint16 length = Length;
     *     opaque label<7..255> = "tls13 " + Label;
     *     opaque context<0..255> = Context;
     * } HkdfLabel;
     */
    
    size_t label_len = strlen(label);
    size_t hkdf_label_len = 2 + 1 + 6 + label_len + 1 + context_len;
    uint8_t *hkdf_label = malloc(hkdf_label_len);
    
    if (!hkdf_label) return -1;
    
    uint8_t *p = hkdf_label;
    
    /* Length (uint16 big endian) */
    *p++ = (okm_len >> 8) & 0xFF;
    *p++ = okm_len & 0xFF;
    
    /* Label */
    *p++ = (uint8_t)(6 + label_len);
    memcpy(p, "tls13 ", 6);
    p += 6;
    memcpy(p, label, label_len);
    p += label_len;
    
    /* Context */
    *p++ = (uint8_t)context_len;
    if (context_len > 0) {
        memcpy(p, context, context_len);
    }
    
    /* Call HKDF-Expand (Using SHA256) */
    int ret = hkdf_expand(secret, secret_len, hkdf_label, hkdf_label_len, okm, okm_len);
    
    free(hkdf_label);
    return ret;
}

/* ========================================================================== */
/* XOF-based KDF (SHAKE256)                                                   */
/* ========================================================================== */

void kdf_shake256(const uint8_t *ikm, size_t ikm_len, const uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len) {
    shake256incctx ctx;
    shake256_inc_init(&ctx);
    shake256_inc_absorb(&ctx, ikm, ikm_len);
    if (info && info_len > 0) {
        shake256_inc_absorb(&ctx, info, info_len);
    }
    shake256_inc_finalize(&ctx);
    shake256_inc_squeeze(okm, okm_len, &ctx);
    shake256_inc_ctx_release(&ctx);
}
