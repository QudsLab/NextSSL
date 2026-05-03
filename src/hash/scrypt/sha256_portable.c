/*
 * Portable SHA-256 + HMAC-SHA-256 + PBKDF2-SHA-256 for scrypt.
 * Replaces the cpusupport.h-dependent version from libcperciva.
 *
 * Public domain / CC0.
 */
#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "insecure_memzero.h"
#include "sysendian.h"
#include "sha256.h"

/* ---------- SHA-256 constants ---------- */

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROR32(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x,y,z)  (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x) (ROR32(x,2)  ^ ROR32(x,13) ^ ROR32(x,22))
#define S1(x) (ROR32(x,6)  ^ ROR32(x,11) ^ ROR32(x,25))
#define s0(x) (ROR32(x,7)  ^ ROR32(x,18) ^ ((x) >> 3))
#define s1(x) (ROR32(x,17) ^ ROR32(x,19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[64], a, b, c, d, e, f, g, h, T1, T2;
    int i;

    for (i = 0; i < 16; i++)
        W[i] = be32dec(block + 4 * i);
    for (i = 16; i < 64; i++)
        W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (i = 0; i < 64; i++) {
        T1 = h + S1(e) + CH(e,f,g) + K[i] + W[i];
        T2 = S0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

/* ---------- SHA-256 streaming API ---------- */

void SHA256_Init(SHA256_CTX *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

void SHA256_Update(SHA256_CTX *ctx, const void *in, size_t len)
{
    const uint8_t *src = (const uint8_t *)in;
    size_t have = (size_t)(ctx->count & 63);
    ctx->count += (uint64_t)len;

    if (have && have + len >= 64) {
        memcpy(ctx->buf + have, src, 64 - have);
        sha256_transform(ctx->state, ctx->buf);
        src += 64 - have;
        len -= 64 - have;
        have = 0;
    }
    while (len >= 64) {
        sha256_transform(ctx->state, src);
        src += 64;
        len -= 64;
    }
    if (len)
        memcpy(ctx->buf + have, src, len);
}

void SHA256_Final(uint8_t digest[32], SHA256_CTX *ctx)
{
    uint64_t bits = ctx->count << 3;
    size_t have = (size_t)(ctx->count & 63);
    uint8_t pad = (have < 56) ? (uint8_t)(56 - have) : (uint8_t)(120 - have);
    uint8_t padbuf[72];

    memset(padbuf, 0, sizeof(padbuf));
    padbuf[0] = 0x80;
    SHA256_Update(ctx, padbuf, pad);
    be64enc(padbuf, bits);
    SHA256_Update(ctx, padbuf, 8);

    for (int i = 0; i < 8; i++)
        be32enc(digest + 4 * i, ctx->state[i]);

    insecure_memzero(ctx, sizeof(*ctx));
}

void SHA256_Buf(const void *in, size_t len, uint8_t digest[32])
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, in, len);
    SHA256_Final(digest, &ctx);
}

/* ---------- HMAC-SHA-256 ---------- */

void HMAC_SHA256_Init(HMAC_SHA256_CTX *ctx, const void *key, size_t keylen)
{
    uint8_t pad[64];
    uint8_t khash[32];
    const uint8_t *k;
    size_t i;

    if (keylen > 64) {
        SHA256_Buf(key, keylen, khash);
        k = khash;
        keylen = 32;
    } else {
        k = (const uint8_t *)key;
    }

    SHA256_Init(&ctx->ictx);
    memset(pad, 0x36, 64);
    for (i = 0; i < keylen; i++)
        pad[i] ^= k[i];
    SHA256_Update(&ctx->ictx, pad, 64);

    SHA256_Init(&ctx->octx);
    memset(pad, 0x5c, 64);
    for (i = 0; i < keylen; i++)
        pad[i] ^= k[i];
    SHA256_Update(&ctx->octx, pad, 64);

    insecure_memzero(khash, sizeof(khash));
    insecure_memzero(pad, sizeof(pad));
}

void HMAC_SHA256_Update(HMAC_SHA256_CTX *ctx, const void *in, size_t len)
{
    SHA256_Update(&ctx->ictx, in, len);
}

void HMAC_SHA256_Final(uint8_t digest[32], HMAC_SHA256_CTX *ctx)
{
    uint8_t ihash[32];
    SHA256_Final(ihash, &ctx->ictx);
    SHA256_Update(&ctx->octx, ihash, 32);
    SHA256_Final(digest, &ctx->octx);
    insecure_memzero(ihash, sizeof(ihash));
}

void HMAC_SHA256_Buf(const void *key, size_t keylen,
                     const void *in, size_t len, uint8_t digest[32])
{
    HMAC_SHA256_CTX ctx;
    HMAC_SHA256_Init(&ctx, key, keylen);
    HMAC_SHA256_Update(&ctx, in, len);
    HMAC_SHA256_Final(digest, &ctx);
}

/* ---------- PBKDF2-SHA-256 ---------- */

void PBKDF2_SHA256(const uint8_t *passwd, size_t passwdlen,
                   const uint8_t *salt, size_t saltlen,
                   uint64_t c, uint8_t *buf, size_t dkLen)
{
    HMAC_SHA256_CTX PShctx, hctx;
    uint8_t U[32], T[32];
    uint8_t ivec[4];
    size_t i, j, clen;
    uint32_t k;

    HMAC_SHA256_Init(&PShctx, passwd, passwdlen);
    HMAC_SHA256_Update(&PShctx, salt, saltlen);

    for (k = 1; dkLen > 0; k++) {
        be32enc(ivec, k);
        memcpy(&hctx, &PShctx, sizeof(HMAC_SHA256_CTX));
        HMAC_SHA256_Update(&hctx, ivec, 4);
        HMAC_SHA256_Final(U, &hctx);
        memcpy(T, U, 32);

        for (i = 1; i < c; i++) {
            HMAC_SHA256_Init(&hctx, passwd, passwdlen);
            HMAC_SHA256_Update(&hctx, U, 32);
            HMAC_SHA256_Final(U, &hctx);
            for (j = 0; j < 32; j++)
                T[j] ^= U[j];
        }

        clen = (dkLen > 32) ? 32 : dkLen;
        memcpy(buf, T, clen);
        buf += clen;
        dkLen -= clen;
    }

    insecure_memzero(&PShctx, sizeof(PShctx));
}
