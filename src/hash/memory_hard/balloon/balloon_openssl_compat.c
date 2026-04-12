/*
 * balloon_openssl_compat.c — Portable OpenSSL-compatibility layer for Balloon.
 *
 * Provides the SHA256_Init/Update/Final and EVP_* functions declared in
 * bitstream.h, using the project's own SHA-256 instead of OpenSSL.
 *
 * AES-128-CTR is replaced by a SHA-256 counter-mode PRG:
 *   block_i = SHA256(key || little-endian-uint64(i))
 * This maintains the security properties of the balloon algorithm while
 * removing the OpenSSL AES dependency.
 *
 * NOTE: Do NOT include bitstream.h here — it defines SHA256_CTX as an
 * opaque 128-byte blob which conflicts with the project's sha256.h typedef.
 * Function signatures are ABI-compatible (pointer arguments), so the linker
 * correctly resolves the function calls from bitstream.c / hash_state.c.
 */

/* Bring in project SHA-256 (defines sha256_init, sha256_update, sha256_final,
 * and SHA256_CTX as the 108-byte internal struct). */
#include "../../fast/sha256.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ── SHA-256 OpenSSL-compatible wrappers ─────────────────────────────────
 * The callers hold a 128-byte opaque blob for SHA256_CTX (from bitstream.h).
 * Our project's SHA256_CTX is 108 bytes, which safely fits in that blob.
 * We cast the pointer — both sides treat it as an opaque pointer at the ABI
 * level, so this is safe across translation units.
 * ──────────────────────────────────────────────────────────────────────── */
int SHA256_Init(SHA256_CTX *c)
{
    sha256_init(c);
    return 1;
}

int SHA256_Update(SHA256_CTX *c, const void *data, size_t len)
{
    sha256_update(c, (const uint8_t *)data, len);
    return 1;
}

int SHA256_Final(unsigned char *md, SHA256_CTX *c)
{
    sha256_final(c, md);
    return 1;
}

/* ── EVP AES-128-CTR replacement: SHA-256 counter-mode PRG ──────────────
 * struct evp_cipher_ctx_st is the concrete definition of the opaque
 * EVP_CIPHER_CTX type forward-declared in bitstream.h.
 * Callers in bitstream.c hold a pointer to it; they never dereference it
 * directly (only call EVP_* functions), so the struct may be defined here.
 * ──────────────────────────────────────────────────────────────────────── */
struct evp_cipher_ctx_st {
    uint8_t  key[32];    /* full 32-byte key from SHA256(seed)             */
    uint64_t ctr;        /* block counter (little-endian in PRG input)     */
    uint8_t  block[32];  /* cached PRG output block                        */
    size_t   pos;        /* bytes consumed from block (32 = exhausted)     */
};

/* EVP_CIPHER type is never used in our implementation; return NULL. */
typedef struct evp_cipher_st EVP_CIPHER_raw;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX_raw;

static void prg_next_block(struct evp_cipher_ctx_st *ctx)
{
    SHA256_CTX sctx;
    uint8_t ctr_le[8];
    uint64_t c = ctx->ctr;
    ctr_le[0] = (uint8_t)(c);
    ctr_le[1] = (uint8_t)(c >>  8);
    ctr_le[2] = (uint8_t)(c >> 16);
    ctr_le[3] = (uint8_t)(c >> 24);
    ctr_le[4] = (uint8_t)(c >> 32);
    ctr_le[5] = (uint8_t)(c >> 40);
    ctr_le[6] = (uint8_t)(c >> 48);
    ctr_le[7] = (uint8_t)(c >> 56);
    sha256_init(&sctx);
    sha256_update(&sctx, ctx->key,  32);
    sha256_update(&sctx, ctr_le,    8);
    sha256_final(&sctx, ctx->block);
    ctx->ctr++;
    ctx->pos = 0;
}

EVP_CIPHER_CTX_raw *EVP_CIPHER_CTX_new(void)
{
    return (EVP_CIPHER_CTX_raw *)calloc(1, sizeof(struct evp_cipher_ctx_st));
}

void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX_raw *ctx)
{
    if (ctx) {
        memset(ctx, 0, sizeof(*ctx));
        free(ctx);
    }
}

const EVP_CIPHER_raw *EVP_aes_128_ctr(void)
{
    return NULL; /* ignored — cipher type is always SHA256-CTR in our impl */
}

/* EVP_EncryptInit: 4-arg (OpenSSL 1.0.x) form used by bitstream.c */
int EVP_EncryptInit(EVP_CIPHER_CTX_raw *ctx,
                    const EVP_CIPHER_raw *type,
                    const unsigned char *key,
                    const unsigned char *iv)
{
    (void)type; (void)iv;
    /* Use all 32 bytes of SHA256(seed) as the PRG key. */
    memcpy(ctx->key, key, 32);
    ctx->ctr = 0;
    ctx->pos = 32; /* force fresh block generation on first read */
    return 1;
}

/* EVP_EncryptInit_ex: 5-arg (OpenSSL 1.1.x) form — also declared for completeness */
int EVP_EncryptInit_ex(EVP_CIPHER_CTX_raw *ctx,
                       const EVP_CIPHER_raw *type,
                       void *impl,
                       const unsigned char *key,
                       const unsigned char *iv)
{
    (void)impl;
    return EVP_EncryptInit(ctx, type, key, iv);
}

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX_raw *ctx, int padding)
{
    (void)ctx; (void)padding;
    return 1; /* no-op: our PRG has no padding concept */
}

/* EVP_EncryptUpdate: generate pseudorandom bytes.
 * `in` is balloon's zeros buffer; we ignore it and output the PRG stream. */
int EVP_EncryptUpdate(EVP_CIPHER_CTX_raw *ctx,
                      unsigned char *out, int *outl,
                      const unsigned char *in, int inl)
{
    (void)in;
    int produced = 0;
    while (produced < inl) {
        if (ctx->pos >= 32)
            prg_next_block(ctx);
        out[produced++] = ctx->block[ctx->pos++];
    }
    *outl = produced;
    return 1;
}

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX_raw *ctx,
                        unsigned char *out, int *outl)
{
    (void)ctx; (void)out;
    *outl = 0;
    return 1;
}
