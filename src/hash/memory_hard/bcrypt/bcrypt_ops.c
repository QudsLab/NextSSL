/* bcrypt_ops.c — hash_ops_t accumulator wrapper for bcrypt (Solar Designer)
 *
 * Source: openwall/crypt_blowfish (public domain).
 * API: _crypt_blowfish_rn(key, setting, output, output_size)
 *      → produces $2b$XX$[22-char-base64-salt][31-char-base64-hash]
 *
 * RESTRICTION: Only valid for seed_hash_derive_ex() CTR seeding where total
 * input is small (<= 2040 bytes).  Must NOT be used with HMAC, HKDF, or
 * PBKDF2 — the construction is undefined and has no security proof.
 *
 * Context fits in HASH_OPS_CTX_MAX (2048):
 *   buf[2040] + len[8] = 2048 bytes exactly.
 *
 * Implementation: uses a fixed deterministic setting string "$2b$10$" + fixed
 * 22-char zero-derived salt. The 31-char bcrypt base64 hash (chars 29-59 of
 * the output) is decoded to 23 raw bytes, first 32 bytes of "output" are
 * filled by XOR-extending the 23 bytes (zero-padding last 9 bytes).
 *
 * Cost: bcrypt rounds=10 (2^10 = 1024 iterations).
 */
#include "../../interface/hash_registry.h"
#include "crypt_blowfish.h"
#include "../../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t buf[2040];
    size_t  len;
} bcrypt_ops_ctx_t;

/* Fixed setting string: $2b$10$ + 22-char base64-encoded all-zero salt.
 * bcrypt base64 alphabet: ./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789
 * 16 zero bytes encodes to: "................" (all dots = 0 in bcrypt b64) */
static const char s_bcrypt_setting[30] = "$2b$10$......................";

/* bcrypt base64 decode table — handles the non-standard bcrypt alphabet */
static const int8_t s_b64dec[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, 0, 1,  /* '.', '/' */
    54,55,56,57,58,59,60,61,62,63,-1,-1,-1,-1,-1,-1,  /* '0'-'9' */
    -1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,  /* 'A'-'O' */
    17,18,19,20,21,22,23,24,25,26,27,-1,-1,-1,-1,-1,  /* 'P'-'Z' */
    -1,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,  /* 'a'-'o' */
    43,44,45,46,47,48,49,50,51,52,53,-1,-1,-1,-1,-1,  /* 'p'-'z' */
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
};

/* Decode the 31-char bcrypt hash tail into up to 23 raw bytes.
 * bcrypt b64 packs 4 chars → 3 bytes.
 * 31 chars = 10 * 3 + 1 char remainder → 10 full triples (30 bytes) + partial.
 * The bcrypt standard encodes exactly 24 bytes (192 bits) of hash as 31 b64 chars.
 */
static void bcrypt_b64_decode(const char *s, size_t slen, uint8_t *out, size_t outlen) {
    size_t si = 0, oi = 0;
    while (si + 2 < slen && oi < outlen) {
        int a = s_b64dec[(unsigned char)s[si]];
        int b = s_b64dec[(unsigned char)s[si+1]];
        int c = s_b64dec[(unsigned char)s[si+2]];
        if (a < 0 || b < 0 || c < 0) break;
        out[oi++]     = (uint8_t)((a << 2) | (b >> 4));
        if (oi < outlen) out[oi++] = (uint8_t)((b << 4) | (c >> 2));
        if (si + 3 < slen && oi < outlen) {
            int d = s_b64dec[(unsigned char)s[si+3]];
            if (d >= 0) out[oi++] = (uint8_t)((c << 6) | d);
        }
        si += 4;
    }
}

static void bcrypt_ops_init(void *c) {
    bcrypt_ops_ctx_t *ctx = (bcrypt_ops_ctx_t *)c;
    ctx->len = 0;
}

static void bcrypt_ops_update(void *c, const uint8_t *d, size_t l) {
    bcrypt_ops_ctx_t *ctx = (bcrypt_ops_ctx_t *)c;
    size_t room = sizeof(ctx->buf) - ctx->len;
    if (l > room) l = room;
    memcpy(ctx->buf + ctx->len, d, l);
    ctx->len += l;
}

#define BCRYPT_OUTPUT_LEN 61  /* 60-char hash + NUL */

static void bcrypt_ops_final(void *c, uint8_t *out) {
    bcrypt_ops_ctx_t *ctx = (bcrypt_ops_ctx_t *)c;

    /* bcrypt expects a null-terminated password string */
    uint8_t pwbuf[2041];
    memcpy(pwbuf, ctx->buf, ctx->len);
    pwbuf[ctx->len] = '\0';

    char output[BCRYPT_OUTPUT_LEN];
    memset(output, 0, sizeof(output));

    _crypt_blowfish_rn((const char *)pwbuf, s_bcrypt_setting,
                       output, (int)sizeof(output));

    /* Decode the 31-char hash portion (chars 29-59) to 24 raw bytes,
     * then take first 32 bytes (zero-pad the last 8 bytes). */
    memset(out, 0, 32);
    if (output[0] != '\0') {
        /* bcrypt output: "$2b$10$" (7) + 22-char salt + 31-char hash = 60 chars */
        bcrypt_b64_decode(output + 29, 31, out, 32);
    }

    secure_zero(ctx->buf, ctx->len);
    secure_zero(pwbuf, ctx->len + 1);
    ctx->len = 0;
}

const hash_ops_t bcrypt_ops = {
    .name        = "bcrypt",
    .digest_size = 32,
    .block_size  = 72,   /* bcrypt max password length is 72 bytes */
    .usage_flags = HASH_USAGE_POW | HASH_USAGE_SEED,
    .init        = bcrypt_ops_init,
    .update      = bcrypt_ops_update,
    .final       = bcrypt_ops_final,
    .wu_per_eval = 1024.0,   /* 2^10 iterations */
    .mu_per_eval = 0.004,    /* ~4 KiB P/S-boxes */
    .parallelism = 1
};
