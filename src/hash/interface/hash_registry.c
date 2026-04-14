/* hash_registry.c — Hash algorithm registry implementation (Plan 202)
 *
 * Provides wrapper functions that adapt each hash algorithm's concrete API
 * (which differ in argument order and ctx type) to the uniform hash_ops_t
 * vtable interface: init(void*), update(void*, data, len), final(void*, out).
 */
#include "hash_registry.h"

#include "../fast/sha224.h"
#include "../fast/sha256.h"
#include "../fast/sha384.h"
#include "../fast/sha512.h"
#include "../blake/blake2b.h"
#include "../blake/blake2s.h"
#include "../blake/blake3.h"
#include "../sponge/sha3_224.h"
#include "../sponge/sha3.h"
#include "../sponge/sha3_384.h"

#include <string.h>
#include <stddef.h>
#include <stdint.h>

/* =========================================================================
 * SHA-224
 * ========================================================================= */
static void sha224_ops_init  (void *c)                               { sha224_init((SHA224_CTX *)c); }
static void sha224_ops_update(void *c, const uint8_t *d, size_t l)  { sha224_update((SHA224_CTX *)c, d, l); }
static void sha224_ops_final (void *c, uint8_t *out)                 { sha224_final((SHA224_CTX *)c, out); }

const hash_ops_t sha224_ops = {
    .name        = "sha224",
    .digest_size = SHA224_DIGEST_LENGTH,
    .block_size  = SHA224_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha224_ops_init,
    .update      = sha224_ops_update,
    .final       = sha224_ops_final,
    .wu_per_eval = 1.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA-256
 * ========================================================================= */
static void sha256_ops_init  (void *c)                               { sha256_init((SHA256_CTX *)c); }
static void sha256_ops_update(void *c, const uint8_t *d, size_t l)  { sha256_update((SHA256_CTX *)c, d, l); }
static void sha256_ops_final (void *c, uint8_t *out)                 { sha256_final((SHA256_CTX *)c, out); }

const hash_ops_t sha256_ops = {
    .name        = "sha256",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha256_ops_init,
    .update      = sha256_ops_update,
    .final       = sha256_ops_final,
    .wu_per_eval = 1.2,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA-384 (shares SHA512_CTX with sha512)
 * ========================================================================= */
static void sha384_ops_init  (void *c)                               { sha384_init((SHA512_CTX *)c); }
static void sha384_ops_update(void *c, const uint8_t *d, size_t l)  { sha512_update((SHA512_CTX *)c, d, l); }
static void sha384_ops_final (void *c, uint8_t *out)                 { sha384_final(out, (SHA512_CTX *)c); }

const hash_ops_t sha384_ops = {
    .name        = "sha384",
    .digest_size = SHA384_DIGEST_LENGTH,
    .block_size  = 128,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha384_ops_init,
    .update      = sha384_ops_update,
    .final       = sha384_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA-512
 * ========================================================================= */
static void sha512_ops_init  (void *c)                               { sha512_init((SHA512_CTX *)c); }
static void sha512_ops_update(void *c, const uint8_t *d, size_t l)  { sha512_update((SHA512_CTX *)c, d, l); }
static void sha512_ops_final (void *c, uint8_t *out)                 { sha512_final(out, (SHA512_CTX *)c); }

const hash_ops_t sha512_ops = {
    .name        = "sha512",
    .digest_size = SHA512_DIGEST_LENGTH,
    .block_size  = 128,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha512_ops_init,
    .update      = sha512_ops_update,
    .final       = sha512_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * BLAKE2b-512 (default 64-byte output)
 * ========================================================================= */
static void blake2b_ops_init  (void *c)                              { blake2b_init((BLAKE2B_CTX *)c, BLAKE2B_OUTBYTES); }
static void blake2b_ops_update(void *c, const uint8_t *d, size_t l) { blake2b_update((BLAKE2B_CTX *)c, d, l); }
static void blake2b_ops_final (void *c, uint8_t *out)               { blake2b_final((BLAKE2B_CTX *)c, out, BLAKE2B_OUTBYTES); }

const hash_ops_t blake2b_ops = {
    .name        = "blake2b",
    .digest_size = BLAKE2B_OUTBYTES,
    .block_size  = BLAKE2B_BLOCKBYTES,
    .usage_flags = HASH_USAGE_ALL,
    .init        = blake2b_ops_init,
    .update      = blake2b_ops_update,
    .final       = blake2b_ops_final,
    .wu_per_eval = 0.8,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * BLAKE2s-256 (default 32-byte output)
 * ========================================================================= */
static void blake2s_ops_init  (void *c)                              { blake2s_init((BLAKE2S_CTX *)c, BLAKE2S_OUTBYTES); }
static void blake2s_ops_update(void *c, const uint8_t *d, size_t l) { blake2s_update((BLAKE2S_CTX *)c, d, l); }
static void blake2s_ops_final (void *c, uint8_t *out)               { blake2s_final((BLAKE2S_CTX *)c, out, BLAKE2S_OUTBYTES); }

const hash_ops_t blake2s_ops = {
    .name        = "blake2s",
    .digest_size = BLAKE2S_OUTBYTES,
    .block_size  = BLAKE2S_BLOCKBYTES,
    .usage_flags = HASH_USAGE_ALL,
    .init        = blake2s_ops_init,
    .update      = blake2s_ops_update,
    .final       = blake2s_ops_final,
    .wu_per_eval = 0.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * BLAKE3-256 (default 32-byte output)
 * ========================================================================= */
static void blake3_ops_init  (void *c)                               { blake3_hasher_init((blake3_hasher *)c); }
static void blake3_ops_update(void *c, const uint8_t *d, size_t l)  { blake3_hasher_update((blake3_hasher *)c, d, l); }
static void blake3_ops_final (void *c, uint8_t *out)                 { blake3_hasher_finalize((blake3_hasher *)c, out, BLAKE3_OUT_LEN); }

const hash_ops_t blake3_ops = {
    .name        = "blake3",
    .digest_size = BLAKE3_OUT_LEN,
    .block_size  = BLAKE3_BLOCK_LEN,
    .usage_flags = HASH_USAGE_ALL,
    .init        = blake3_ops_init,
    .update      = blake3_ops_update,
    .final       = blake3_ops_final,
    .wu_per_eval = 0.4,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA3-224
 * ========================================================================= */
static void sha3_224_ops_init  (void *c)                             { sha3_224_init((SHA3_224_CTX *)c); }
static void sha3_224_ops_update(void *c, const uint8_t *d, size_t l){ sha3_224_update((SHA3_224_CTX *)c, d, l); }
static void sha3_224_ops_final (void *c, uint8_t *out)              { sha3_224_final(out, (SHA3_224_CTX *)c); }

const hash_ops_t sha3_224_ops = {
    .name        = "sha3-224",
    .digest_size = SHA3_224_DIGEST_LENGTH,
    .block_size  = 144,   /* SHA3-224 rate = 1152 bits = 144 bytes */
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha3_224_ops_init,
    .update      = sha3_224_ops_update,
    .final       = sha3_224_ops_final,
    .wu_per_eval = 1.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA3-256  (uses shared SHA3_CTX)
 * ========================================================================= */
static void sha3_256_ops_init  (void *c)                             { sha3_256_init((SHA3_CTX *)c); }
static void sha3_256_ops_update(void *c, const uint8_t *d, size_t l){ sha3_update((SHA3_CTX *)c, d, l); }
static void sha3_256_ops_final (void *c, uint8_t *out)              { sha3_final(out, (SHA3_CTX *)c); }

const hash_ops_t sha3_256_ops = {
    .name        = "sha3-256",
    .digest_size = SHA3_256_DIGEST_LENGTH,
    .block_size  = 136,   /* SHA3-256 rate = 1088 bits = 136 bytes */
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha3_256_ops_init,
    .update      = sha3_256_ops_update,
    .final       = sha3_256_ops_final,
    .wu_per_eval = 1.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA3-384  (uses SHA3_384_CTX)
 * ========================================================================= */
static void sha3_384_ops_init  (void *c)                             { sha3_384_init((SHA3_384_CTX *)c); }
static void sha3_384_ops_update(void *c, const uint8_t *d, size_t l){ sha3_384_update((SHA3_384_CTX *)c, d, l); }
static void sha3_384_ops_final (void *c, uint8_t *out)              { sha3_384_final(out, (SHA3_384_CTX *)c); }

const hash_ops_t sha3_384_ops = {
    .name        = "sha3-384",
    .digest_size = SHA3_384_DIGEST_LENGTH,
    .block_size  = 104,   /* SHA3-384 rate = 832 bits = 104 bytes */
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha3_384_ops_init,
    .update      = sha3_384_ops_update,
    .final       = sha3_384_ops_final,
    .wu_per_eval = 1.8,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA3-512  (uses shared SHA3_CTX)
 * ========================================================================= */
static void sha3_512_ops_init  (void *c)                             { sha3_512_init((SHA3_CTX *)c); }
static void sha3_512_ops_update(void *c, const uint8_t *d, size_t l){ sha3_update((SHA3_CTX *)c, d, l); }
static void sha3_512_ops_final (void *c, uint8_t *out)              { sha3_final(out, (SHA3_CTX *)c); }

const hash_ops_t sha3_512_ops = {
    .name        = "sha3-512",
    .digest_size = SHA3_512_DIGEST_LENGTH,
    .block_size  = 72,    /* SHA3-512 rate = 576 bits = 72 bytes */
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha3_512_ops_init,
    .update      = sha3_512_ops_update,
    .final       = sha3_512_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Keccak-256  (uses shared SHA3_CTX)
 * ========================================================================= */
static void keccak256_ops_init  (void *c)                            { keccak_256_init((SHA3_CTX *)c); }
/* update and final reuse SHA3 path — same compression function */
static void keccak256_ops_update(void *c, const uint8_t *d, size_t l){ sha3_update((SHA3_CTX *)c, d, l); }
static void keccak256_ops_final (void *c, uint8_t *out)             { sha3_final_custom(out, (SHA3_CTX *)c, 0x01); }

const hash_ops_t keccak256_ops = {
    .name        = "keccak256",
    .digest_size = KECCAK_256_DIGEST_LENGTH,
    .block_size  = 136,
    .usage_flags = HASH_USAGE_ALL,
    .init        = keccak256_ops_init,
    .update      = keccak256_ops_update,
    .final       = keccak256_ops_final,
    .wu_per_eval = 1.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHAKE-128  (XOF — output fixed to 32 bytes for hash_ops_t compatibility)
 * ========================================================================= */
#include "../sponge/shake.h"

static void shake128_ops_init  (void *c)                              { shake128_init((SHAKE_CTX *)c); }
static void shake128_ops_update(void *c, const uint8_t *d, size_t l)  { shake_update((SHAKE_CTX *)c, d, l); }
static void shake128_ops_final (void *c, uint8_t *out)                {
    shake_final((SHAKE_CTX *)c);
    shake_squeeze((SHAKE_CTX *)c, out, 32);
}

const hash_ops_t shake128_ops = {
    .name        = "shake128",
    .digest_size = 32,
    .block_size  = 168,   /* rate = 1344 bits = 168 bytes */
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = shake128_ops_init,
    .update      = shake128_ops_update,
    .final       = shake128_ops_final,
    .wu_per_eval = 1.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHAKE-256  (XOF — output fixed to 64 bytes)
 * ========================================================================= */
static void shake256_ops_init  (void *c)                              { shake256_init((SHAKE_CTX *)c); }
static void shake256_ops_update(void *c, const uint8_t *d, size_t l)  { shake_update((SHAKE_CTX *)c, d, l); }
static void shake256_ops_final (void *c, uint8_t *out)                {
    shake_final((SHAKE_CTX *)c);
    shake_squeeze((SHAKE_CTX *)c, out, 64);
}

const hash_ops_t shake256_ops = {
    .name        = "shake256",
    .digest_size = 64,
    .block_size  = 136,   /* rate = 1088 bits = 136 bytes */
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = shake256_ops_init,
    .update      = shake256_ops_update,
    .final       = shake256_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Argon2 accumulator adapter (Plan 205 Phase A / Plan 40003)
 *
 * Argon2 is a KDF, not a streaming hash. This adapter accumulates all
 * update() data into a fixed buffer and calls argon2*_hash_raw() on final().
 *
 * RESTRICTION: Only valid for seed_hash_derive_ex() CTR seeding where total
 * input is small (<= 2016 bytes). Must NOT be used with HMAC, HKDF, or
 * PBKDF2 — the construction is undefined and has no security proof.
 *
 * Context fits in HASH_OPS_CTX_MAX (2048):
 *   buf[2016] + salt[16] + salt_len[1] + _pad[7] + len[8] = 2048 bytes.
 *
 * Salt rules:
 *   salt_len == 0  → use domain-separator s_argon2_ops_salt (deterministic)
 *   salt_len  > 0  → use caller-provided salt from ctx->salt[]
 *   Call argon2_ops_set_salt(ctx, s, len) once before init/update/final.
 * ========================================================================= */
#include "../memory_hard/argon2.h"
#include "../memory_hard/argon2id.h"
#include "../memory_hard/argon2i.h"
#include "../memory_hard/argon2d.h"
#include "../../common/secure_zero.h"
#include <string.h>

typedef struct {
    uint8_t buf[2016];   /* accumulator: input < 2016 bytes                */
    uint8_t salt[16];    /* optional caller-provided salt (Plan 40003)      */
    uint8_t salt_len;    /* 0 = use domain separator; >0 = use salt[]       */
    uint8_t _pad[7];     /* alignment pad — keeps len at offset 2040        */
    size_t  len;         /* bytes accumulated in buf                        */
} argon2_ops_ctx_t;      /* sizeof = 2016+16+1+7+8 = 2048 == HASH_OPS_CTX_MAX */

/* Domain separator for NextSSL seed derivation — fixed, non-zero, non-secret.
 * Used as the default salt when the caller has not configured one explicitly.
 * Not a secret; distinguishes NextSSL argon2 seed usage from generic argon2. */
static const uint8_t s_argon2_ops_salt[16] = {
    'N','X','T','S','L', 0, 'A','G', '2', 0, 0, 0, 0, 0, 0, 0
};

#define ARGON2_OPS_TCOST 2
#define ARGON2_OPS_MCOST 65536  /* 64 MiB */
#define ARGON2_OPS_PAR   1

/* argon2_ops_set_salt — configure override salt before init/update/final
 *
 * ctx      — raw context buffer (allocated by the caller as HASH_OPS_CTX_MAX)
 * salt     — salt bytes to copy; max 16 bytes are used
 * salt_len — length; pass 0 to revert to domain-separator default
 *
 * The salt persists across multiple init/update/final cycles on the same ctx.
 */
void argon2_ops_set_salt(void *ctx_raw, const uint8_t *salt, size_t salt_len)
{
    argon2_ops_ctx_t *ctx = (argon2_ops_ctx_t *)ctx_raw;
    if (!ctx || !salt || salt_len == 0) {
        if (ctx) ctx->salt_len = 0;
        return;
    }
    size_t copy = salt_len > sizeof(ctx->salt) ? sizeof(ctx->salt) : salt_len;
    memcpy(ctx->salt, salt, copy);
    ctx->salt_len = (uint8_t)copy;
}

static void argon2_ops_init_common(void *c) {
    argon2_ops_ctx_t *ctx = (argon2_ops_ctx_t *)c;
    ctx->len = 0;
    /* salt field intentionally NOT reset — survives across init calls */
}

static void argon2_ops_update_common(void *c, const uint8_t *d, size_t l) {
    argon2_ops_ctx_t *ctx = (argon2_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;  /* silent cap — inputs are always small in seeding */
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

/* --- Argon2id --- */
static void argon2id_ops_init  (void *c)                              { argon2_ops_init_common(c); }
static void argon2id_ops_update(void *c, const uint8_t *d, size_t l)  { argon2_ops_update_common(c, d, l); }
static void argon2id_ops_final (void *c, uint8_t *out) {
    argon2_ops_ctx_t *ctx = (argon2_ops_ctx_t *)c;
    const uint8_t *s   = ctx->salt_len ? ctx->salt : s_argon2_ops_salt;
    size_t         sln = ctx->salt_len ? ctx->salt_len : sizeof(s_argon2_ops_salt);
    argon2id_hash_raw(ARGON2_OPS_TCOST, ARGON2_OPS_MCOST, ARGON2_OPS_PAR,
                      ctx->buf, ctx->len, s, sln, out, 32);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t argon2id_ops = {
    .name        = "argon2id",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = argon2id_ops_init,
    .update      = argon2id_ops_update,
    .final       = argon2id_ops_final,
    .wu_per_eval = 5000.0,
    .mu_per_eval = 64.0,
    .parallelism = 1
};

/* --- Argon2i --- */
static void argon2i_ops_init  (void *c)                               { argon2_ops_init_common(c); }
static void argon2i_ops_update(void *c, const uint8_t *d, size_t l)   { argon2_ops_update_common(c, d, l); }
static void argon2i_ops_final (void *c, uint8_t *out) {
    argon2_ops_ctx_t *ctx = (argon2_ops_ctx_t *)c;
    const uint8_t *s   = ctx->salt_len ? ctx->salt : s_argon2_ops_salt;
    size_t         sln = ctx->salt_len ? ctx->salt_len : sizeof(s_argon2_ops_salt);
    argon2i_hash_raw(ARGON2_OPS_TCOST, ARGON2_OPS_MCOST, ARGON2_OPS_PAR,
                     ctx->buf, ctx->len, s, sln, out, 32);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t argon2i_ops = {
    .name        = "argon2i",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = argon2i_ops_init,
    .update      = argon2i_ops_update,
    .final       = argon2i_ops_final,
    .wu_per_eval = 5000.0,
    .mu_per_eval = 64.0,
    .parallelism = 1
};

/* --- Argon2d --- */
static void argon2d_ops_init  (void *c)                               { argon2_ops_init_common(c); }
static void argon2d_ops_update(void *c, const uint8_t *d, size_t l)   { argon2_ops_update_common(c, d, l); }
static void argon2d_ops_final (void *c, uint8_t *out) {
    argon2_ops_ctx_t *ctx = (argon2_ops_ctx_t *)c;
    const uint8_t *s   = ctx->salt_len ? ctx->salt : s_argon2_ops_salt;
    size_t         sln = ctx->salt_len ? ctx->salt_len : sizeof(s_argon2_ops_salt);
    argon2d_hash_raw(ARGON2_OPS_TCOST, ARGON2_OPS_MCOST, ARGON2_OPS_PAR,
                     ctx->buf, ctx->len, s, sln, out, 32);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t argon2d_ops = {
    .name        = "argon2d",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = argon2d_ops_init,
    .update      = argon2d_ops_update,
    .final       = argon2d_ops_final,
    .wu_per_eval = 5000.0,
    .mu_per_eval = 64.0,
    .parallelism = 1
};

/* --- Argon2 (compatibility/default entry point) --- */
static void argon2_ops_init  (void *c)                               { argon2_ops_init_common(c); }
static void argon2_ops_update(void *c, const uint8_t *d, size_t l)   { argon2_ops_update_common(c, d, l); }
static void argon2_ops_final (void *c, uint8_t *out) {
    argon2_ops_ctx_t *ctx = (argon2_ops_ctx_t *)c;
    const uint8_t *s   = ctx->salt_len ? ctx->salt : s_argon2_ops_salt;
    size_t         sln = ctx->salt_len ? ctx->salt_len : sizeof(s_argon2_ops_salt);
    argon2_hash(ARGON2_OPS_TCOST, ARGON2_OPS_MCOST, ARGON2_OPS_PAR,
                ctx->buf, ctx->len, s, sln,
                out, 32,
                NULL, 0,
                Argon2_id,
                ARGON2_VERSION_NUMBER);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t argon2_ops = {
    .name        = "argon2",
    .digest_size = 32,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = argon2_ops_init,
    .update      = argon2_ops_update,
    .final       = argon2_ops_final,
    .wu_per_eval = 5000.0,
    .mu_per_eval = 64.0,
    .parallelism = 1
};

/* =========================================================================
 * Legacy hashes — SHA-1, SHA-0
 * All follow (digest, ctx) _final convention confirmed by header audit.
 * ========================================================================= */
#include "../legacy/sha1.h"
#include "../legacy/sha0.h"

static void sha1_ops_init  (void *c)                               { sha1_init((SHA1_CTX *)c); }
static void sha1_ops_update(void *c, const uint8_t *d, size_t l)   { sha1_update((SHA1_CTX *)c, d, l); }
static void sha1_ops_final (void *c, uint8_t *out)                 { sha1_final(out, (SHA1_CTX *)c); }

const hash_ops_t sha1_ops = {
    .name        = "sha1",
    .digest_size = SHA1_DIGEST_LENGTH,
    .block_size  = SHA1_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha1_ops_init,
    .update      = sha1_ops_update,
    .final       = sha1_ops_final,
    .wu_per_eval = 0.8,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

static void sha0_ops_init  (void *c)                               { sha0_init((SHA0_CTX *)c); }
static void sha0_ops_update(void *c, const uint8_t *d, size_t l)   { sha0_update((SHA0_CTX *)c, d, l); }
static void sha0_ops_final (void *c, uint8_t *out)                 { sha0_final(out, (SHA0_CTX *)c); }

const hash_ops_t sha0_ops = {
    .name        = "sha0",
    .digest_size = SHA0_DIGEST_LENGTH,
    .block_size  = SHA0_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED | HASH_USAGE_HMAC,
    .init        = sha0_ops_init,
    .update      = sha0_ops_update,
    .final       = sha0_ops_final,
    .wu_per_eval = 0.8,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Legacy hashes — MD5, MD4, MD2
 * ========================================================================= */
#include "../legacy/md5.h"
#include "../legacy/md4.h"
#include "../legacy/md2.h"

static void md5_ops_init  (void *c)                               { md5_init((MD5_CTX *)c); }
static void md5_ops_update(void *c, const uint8_t *d, size_t l)   { md5_update((MD5_CTX *)c, d, l); }
static void md5_ops_final (void *c, uint8_t *out)                 { md5_final(out, (MD5_CTX *)c); }

const hash_ops_t md5_ops = {
    .name        = "md5",
    .digest_size = MD5_DIGEST_LENGTH,
    .block_size  = MD5_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED | HASH_USAGE_HMAC,
    .init        = md5_ops_init,
    .update      = md5_ops_update,
    .final       = md5_ops_final,
    .wu_per_eval = 0.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

static void md4_ops_init  (void *c)                               { md4_init((MD4_CTX *)c); }
static void md4_ops_update(void *c, const uint8_t *d, size_t l)   { md4_update((MD4_CTX *)c, d, l); }
static void md4_ops_final (void *c, uint8_t *out)                 { md4_final(out, (MD4_CTX *)c); }

const hash_ops_t md4_ops = {
    .name        = "md4",
    .digest_size = MD4_DIGEST_LENGTH,
    .block_size  = MD4_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED | HASH_USAGE_HMAC,
    .init        = md4_ops_init,
    .update      = md4_ops_update,
    .final       = md4_ops_final,
    .wu_per_eval = 0.4,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

static void md2_ops_init  (void *c)                               { md2_init((MD2_CTX *)c); }
static void md2_ops_update(void *c, const uint8_t *d, size_t l)   { md2_update((MD2_CTX *)c, d, l); }
static void md2_ops_final (void *c, uint8_t *out)                 { md2_final(out, (MD2_CTX *)c); }

const hash_ops_t md2_ops = {
    .name        = "md2",
    .digest_size = MD2_DIGEST_LENGTH,
    .block_size  = MD2_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED | HASH_USAGE_HMAC,
    .init        = md2_ops_init,
    .update      = md2_ops_update,
    .final       = md2_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * NT-HASH — accumulator adapter (no streaming API in nt.h)
 *
 * nt.h only provides one-shot nt_hash_unicode(utf16le, len, digest).
 * The adapter accumulates bytes and passes the buffer as raw UTF-16LE.
 * This is the correct interpretation: NTLM hash = MD4(UTF-16LE(password)).
 * When using this via hash_ops_t, the caller must supply UTF-16LE bytes
 * directly. Buffer limit: 2040 bytes = 1020 UTF-16LE characters.
 * ========================================================================= */
#include "../legacy/nt.h"
#include "../legacy/tiger.h"

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} nt_ops_ctx_t;

static void nt_ops_init  (void *c) {
    nt_ops_ctx_t *ctx = (nt_ops_ctx_t *)c;
    ctx->len = 0;
}

static void nt_ops_update(void *c, const uint8_t *d, size_t l) {
    nt_ops_ctx_t *ctx = (nt_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

static void nt_ops_final(void *c, uint8_t *out) {
    nt_ops_ctx_t *ctx = (nt_ops_ctx_t *)c;
    nt_hash_unicode(ctx->buf, ctx->len, out);
    secure_zero(ctx->buf, ctx->len);
    ctx->len = 0;
}

const hash_ops_t nt_ops = {
    .name        = "nt",
    .digest_size = NT_HASH_LENGTH,
    .block_size  = 64,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED | HASH_USAGE_HMAC,
    .init        = nt_ops_init,
    .update      = nt_ops_update,
    .final       = nt_ops_final,
    .wu_per_eval = 0.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Tiger (192-bit)
 * ========================================================================= */
static void tiger_ops_init  (void *c)                               { tiger_init((TIGER_CTX *)c); }
static void tiger_ops_update(void *c, const uint8_t *d, size_t l)   { tiger_update((TIGER_CTX *)c, d, l); }
static void tiger_ops_final (void *c, uint8_t *out)                 { tiger_final(out, (TIGER_CTX *)c); }

const hash_ops_t tiger_ops = {
    .name        = "tiger",
    .digest_size = TIGER_DIGEST_LENGTH,
    .block_size  = TIGER_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED | HASH_USAGE_HMAC,
    .init        = tiger_ops_init,
    .update      = tiger_ops_update,
    .final       = tiger_ops_final,
    .wu_per_eval = 1.2,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * RIPEMD family
 * ========================================================================= */
#include "../legacy/ripemd128.h"
#include "../legacy/ripemd160.h"
#include "../legacy/ripemd256.h"
#include "../legacy/ripemd320.h"

static void ripemd128_ops_init  (void *c)                               { ripemd128_init((RIPEMD128_CTX *)c); }
static void ripemd128_ops_update(void *c, const uint8_t *d, size_t l)   { ripemd128_update((RIPEMD128_CTX *)c, d, l); }
static void ripemd128_ops_final (void *c, uint8_t *out)                 { ripemd128_final(out, (RIPEMD128_CTX *)c); }

const hash_ops_t ripemd128_ops = {
    .name        = "ripemd128",
    .digest_size = RIPEMD128_DIGEST_LENGTH,
    .block_size  = RIPEMD128_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = ripemd128_ops_init,
    .update      = ripemd128_ops_update,
    .final       = ripemd128_ops_final,
    .wu_per_eval = 1.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

static void ripemd160_ops_init  (void *c)                               { ripemd160_init((RIPEMD160_CTX *)c); }
static void ripemd160_ops_update(void *c, const uint8_t *d, size_t l)   { ripemd160_update((RIPEMD160_CTX *)c, d, l); }
static void ripemd160_ops_final (void *c, uint8_t *out)                 { ripemd160_final(out, (RIPEMD160_CTX *)c); }

const hash_ops_t ripemd160_ops = {
    .name        = "ripemd160",
    .digest_size = RIPEMD160_DIGEST_LENGTH,
    .block_size  = RIPEMD160_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = ripemd160_ops_init,
    .update      = ripemd160_ops_update,
    .final       = ripemd160_ops_final,
    .wu_per_eval = 1.2,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

static void ripemd256_ops_init  (void *c)                               { ripemd256_init((RIPEMD256_CTX *)c); }
static void ripemd256_ops_update(void *c, const uint8_t *d, size_t l)   { ripemd256_update((RIPEMD256_CTX *)c, d, l); }
static void ripemd256_ops_final (void *c, uint8_t *out)                 { ripemd256_final(out, (RIPEMD256_CTX *)c); }

const hash_ops_t ripemd256_ops = {
    .name        = "ripemd256",
    .digest_size = RIPEMD256_DIGEST_LENGTH,
    .block_size  = RIPEMD256_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = ripemd256_ops_init,
    .update      = ripemd256_ops_update,
    .final       = ripemd256_ops_final,
    .wu_per_eval = 1.3,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

static void ripemd320_ops_init  (void *c)                               { ripemd320_init((RIPEMD320_CTX *)c); }
static void ripemd320_ops_update(void *c, const uint8_t *d, size_t l)   { ripemd320_update((RIPEMD320_CTX *)c, d, l); }
static void ripemd320_ops_final (void *c, uint8_t *out)                 { ripemd320_final(out, (RIPEMD320_CTX *)c); }

const hash_ops_t ripemd320_ops = {
    .name        = "ripemd320",
    .digest_size = RIPEMD320_DIGEST_LENGTH,
    .block_size  = RIPEMD320_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = ripemd320_ops_init,
    .update      = ripemd320_ops_update,
    .final       = ripemd320_ops_final,
    .wu_per_eval = 1.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Whirlpool
 * ========================================================================= */
#include "../legacy/whirlpool.h"

static void whirlpool_ops_init  (void *c)                               { whirlpool_init((WHIRLPOOL_CTX *)c); }
static void whirlpool_ops_update(void *c, const uint8_t *d, size_t l)   { whirlpool_update((WHIRLPOOL_CTX *)c, d, l); }
static void whirlpool_ops_final (void *c, uint8_t *out)                 { whirlpool_final(out, (WHIRLPOOL_CTX *)c); }

const hash_ops_t whirlpool_ops = {
    .name        = "whirlpool",
    .digest_size = WHIRLPOOL_DIGEST_LENGTH,
    .block_size  = WHIRLPOOL_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = whirlpool_ops_init,
    .update      = whirlpool_ops_update,
    .final       = whirlpool_ops_final,
    .wu_per_eval = 3.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * HAS-160  (Korean KISA standard)
 * ========================================================================= */
#include "../legacy/has160.h"

static void has160_ops_init  (void *c)                               { has160_init((HAS160_CTX *)c); }
static void has160_ops_update(void *c, const uint8_t *d, size_t l)   { has160_update((HAS160_CTX *)c, d, l); }
static void has160_ops_final (void *c, uint8_t *out)                 { has160_final(out, (HAS160_CTX *)c); }

const hash_ops_t has160_ops = {
    .name        = "has160",
    .digest_size = HAS160_DIGEST_LENGTH,
    .block_size  = HAS160_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED | HASH_USAGE_HMAC,
    .init        = has160_ops_init,
    .update      = has160_ops_update,
    .final       = has160_ops_final,
    .wu_per_eval = 0.9,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

#include "../fast/sha512_224.h"
#include "../fast/sha512_256.h"
#include "../sponge/sp800_185/kmac.h"

/* =========================================================================
 * SHA-512/224  (FIPS 180-4 §5.3.6.1, Plan 207 Phase C)
 * ========================================================================= */
static void sha512_224_ops_init  (void *c) { sha512_224_init((SHA512_224_CTX *)c); }
static void sha512_224_ops_update(void *c, const uint8_t *d, size_t l) { sha512_update((SHA512_224_CTX *)c, d, l); }
static void sha512_224_ops_final (void *c, uint8_t *out) { sha512_224_final(out, (SHA512_224_CTX *)c); }

const hash_ops_t sha512_224_ops = {
    .name        = "sha512-224",
    .digest_size = SHA512_224_DIGEST_LENGTH,
    .block_size  = SHA512_224_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha512_224_ops_init,
    .update      = sha512_224_ops_update,
    .final       = sha512_224_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * SHA-512/256  (FIPS 180-4 §5.3.6.2, Plan 207 Phase C)
 * ========================================================================= */
static void sha512_256_ops_init  (void *c) { sha512_256_init((SHA512_256_CTX *)c); }
static void sha512_256_ops_update(void *c, const uint8_t *d, size_t l) { sha512_update((SHA512_256_CTX *)c, d, l); }
static void sha512_256_ops_final (void *c, uint8_t *out) { sha512_256_final(out, (SHA512_256_CTX *)c); }

const hash_ops_t sha512_256_ops = {
    .name        = "sha512-256",
    .digest_size = SHA512_256_DIGEST_LENGTH,
    .block_size  = SHA512_256_BLOCK_SIZE,
    .usage_flags = HASH_USAGE_ALL,
    .init        = sha512_256_ops_init,
    .update      = sha512_256_ops_update,
    .final       = sha512_256_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * KMAC-128  (NIST SP 800-185, Plan 207 Phase D)
 * Unkeyed (empty K, empty S) — equivalent to cSHAKE128 with N="KMAC".
 * Fixed 32-byte output.  Key this via kmac128_compute() for actual MAC use.
 * usage_flags: HMAC | POW | SEED — KMAC itself IS the keyed primitive;
 *              wrapping it in PBKDF2/HKDF (which use HMAC internally) makes
 *              no sense and is not a defined standard construction.
 * ========================================================================= */
static void kmac128_ops_init  (void *c) { kmac128_ops_init_fn((KMAC_CTX *)c); }
static void kmac128_ops_update(void *c, const uint8_t *d, size_t l) { kmac_update((KMAC_CTX *)c, d, l); }
static void kmac128_ops_final (void *c, uint8_t *out) { kmac_final((KMAC_CTX *)c, out); }

const hash_ops_t kmac128_ops = {
    .name        = "kmac128",
    .digest_size = 32,
    .block_size  = 168,   /* cSHAKE128 rate */
    .usage_flags = HASH_USAGE_HMAC | HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = kmac128_ops_init,
    .update      = kmac128_ops_update,
    .final       = kmac128_ops_final,
    .wu_per_eval = 1.5,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * KMAC-256  (NIST SP 800-185, Plan 207 Phase D)
 * Fixed 64-byte output.
 * ========================================================================= */
static void kmac256_ops_init  (void *c) { kmac256_ops_init_fn((KMAC_CTX *)c); }
static void kmac256_ops_update(void *c, const uint8_t *d, size_t l) { kmac_update((KMAC_CTX *)c, d, l); }
static void kmac256_ops_final (void *c, uint8_t *out) { kmac_final((KMAC_CTX *)c, out); }

const hash_ops_t kmac256_ops = {
    .name        = "kmac256",
    .digest_size = 64,
    .block_size  = 136,   /* cSHAKE256 rate */
    .usage_flags = HASH_USAGE_HMAC | HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = kmac256_ops_init,
    .update      = kmac256_ops_update,
    .final       = kmac256_ops_final,
    .wu_per_eval = 2.0,
    .mu_per_eval = 0.0,
    .parallelism = 1
};

/* =========================================================================
 * Registry table
 * ========================================================================= */
static const hash_ops_t *s_registry[HASH_REGISTRY_MAX];
static int s_count = 0;
static int s_initialised = 0;

int hash_register(const hash_ops_t *ops) {
    if (!ops) return -1;
    if (ops->usage_flags == 0) return -1; /* caller forgot to set usage_flags */
    if (s_count >= HASH_REGISTRY_MAX) return -1;
    s_registry[s_count++] = ops;
    return 0;
}

/* ---- Alias table: alternative names → canonical registry names ---- */
static const struct { const char *alias; const char *canonical; } s_aliases[] = {
    { "nthash",     "nt"         },
    { "sha512/224", "sha512-224" },
    { "sha512/256", "sha512-256" },
};
#define ALIAS_COUNT (sizeof(s_aliases) / sizeof(s_aliases[0]))

const hash_ops_t *hash_lookup(const char *name) {
    if (!name) return NULL;
    /* Resolve aliases first */
    for (size_t a = 0; a < ALIAS_COUNT; a++) {
        if (strcmp(name, s_aliases[a].alias) == 0) {
            name = s_aliases[a].canonical;
            break;
        }
    }
    for (int i = 0; i < s_count; i++) {
        if (strcmp(s_registry[i]->name, name) == 0)
            return s_registry[i];
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Typed accessors — return NULL if the hash doesn't support the operation.
 * ------------------------------------------------------------------------- */
const hash_ops_t *hash_for_hmac(const char *name) {
    const hash_ops_t *h = hash_lookup(name);
    return (h && (h->usage_flags & HASH_USAGE_HMAC)) ? h : NULL;
}

const hash_ops_t *hash_for_pbkdf2(const char *name) {
    const hash_ops_t *h = hash_lookup(name);
    return (h && (h->usage_flags & HASH_USAGE_PBKDF2)) ? h : NULL;
}

const hash_ops_t *hash_for_hkdf(const char *name) {
    const hash_ops_t *h = hash_lookup(name);
    return (h && (h->usage_flags & HASH_USAGE_HKDF)) ? h : NULL;
}

const hash_ops_t *hash_for_pow(const char *name) {
    const hash_ops_t *h = hash_lookup(name);
    return (h && (h->usage_flags & HASH_USAGE_POW)) ? h : NULL;
}

const hash_ops_t *hash_for_seed(const char *name) {
    const hash_ops_t *h = hash_lookup(name);
    return (h && (h->usage_flags & HASH_USAGE_SEED)) ? h : NULL;
}

void hash_registry_init(void) {
    if (s_initialised) return;
    s_initialised = 1;

    /* --- Fast SHA-2 --- */
    hash_register(&sha224_ops);
    hash_register(&sha256_ops);
    hash_register(&sha384_ops);
    hash_register(&sha512_ops);
    hash_register(&sha512_224_ops);
    hash_register(&sha512_256_ops);

    /* --- BLAKE --- */
    hash_register(&blake2b_ops);
    hash_register(&blake2s_ops);
    hash_register(&blake3_ops);

    /* --- SHA-3 / Keccak --- */
    hash_register(&sha3_224_ops);
    hash_register(&sha3_256_ops);
    hash_register(&sha3_384_ops);
    hash_register(&sha3_512_ops);
    hash_register(&keccak256_ops);

    /* --- XOF / sponge MAC --- */
    hash_register(&shake128_ops);
    hash_register(&shake256_ops);
    hash_register(&kmac128_ops);
    hash_register(&kmac256_ops);

    /* --- National standard hashes (GB/T, SM3) --- */
    hash_register(&sm3_ops);

/* --- Memory-hard (CTR seed use only — NOT for HMAC/HKDF/PBKDF2) --- */
    hash_register(&argon2id_ops);
    hash_register(&argon2i_ops);
    hash_register(&argon2d_ops);
    hash_register(&scrypt_ops);
    hash_register(&yescrypt_ops);
    hash_register(&catena_ops);
    hash_register(&lyra2_ops);
    hash_register(&bcrypt_ops);
    hash_register(&pomelo_ops);
    hash_register(&makwa_ops);
    hash_register(&ripemd128_ops);
    hash_register(&ripemd160_ops);
    hash_register(&ripemd256_ops);
    hash_register(&ripemd320_ops);
    hash_register(&whirlpool_ops);
    hash_register(&has160_ops);

    /* --- Legacy ⚠️ --- */
    hash_register(&sha1_ops);
    hash_register(&sha0_ops);
    hash_register(&md5_ops);
    hash_register(&md4_ops);
    hash_register(&md2_ops);
    hash_register(&nt_ops);
    hash_register(&tiger_ops);

    /* --- Skein --- */
    hash_register(&skein256_ops);
    hash_register(&skein512_ops);
    hash_register(&skein1024_ops);
}
