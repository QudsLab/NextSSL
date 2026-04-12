/* makwa.c — Portable Makwa password-hashing (no OpenSSL, no external bignum).
 *
 * Implements:
 *   int makwa_hash(const uint8_t *password, size_t passlen,
 *                  const uint8_t *salt,     size_t saltlen,
 *                  uint32_t work_factor,
 *                  uint8_t *out, size_t outlen);
 *
 * Based on the Makwa algorithm by Thomas Pornin (PHC 2015).
 * Modulus N = PHC_PUB2048[8..263] from example/MAKWA/Makwa-PHC-20150422/c/phc.c
 * (generated 2014-02-20; private key not retained per the README).
 *
 * Algorithm:
 *   1. Pre-hash: derive 256 bytes from (password, salt) via counter-mode SHA-256.
 *      block[i] = SHA-256(BE32(i) || password || salt), i = 0..7.
 *      Top byte is forced to 0 so x < 2^2040 < N (conservative range reduction).
 *   2. Load x as 64 little-endian uint32 limbs (2048-bit big integer).
 *   3. Convert to Montgomery form: x_M = x * R mod N, R = 2^2048.
 *   4. Square work_factor times in Montgomery domain.
 *   5. Convert back: x = x_M * R^{-1} mod N.
 *   6. Post-hash: SHA-256(x_bytes || salt) -> first outlen bytes.
 *
 * Montgomery params are precomputed once (lazy static init) and reused.
 */

#include "makwa.h"
#include "../../fast/sha256.h"
#include "../../../common/secure_zero.h"
#include <string.h>
#include <stdint.h>

/* ────────────────────────────────────────────────────────────────────────
 * 2048-bit big-integer representation:
 *   64 × uint32_t limbs, little-endian (limb[0] = least significant word).
 * ──────────────────────────────────────────────────────────────────────── */
#define NLIMBS 64
typedef uint32_t bn_t[NLIMBS];

/* ────────────────────────────────────────────────────────────────────────
 * PHC_PUB2048 modulus N (256 bytes, big-endian).
 * Source: example/MAKWA/Makwa-PHC-20150422/c/phc.c, bytes [8..263].
 * This is a 2048-bit RSA-style modulus whose private factorisation was
 * discarded by the author after key generation.
 * ──────────────────────────────────────────────────────────────────────── */
static const uint8_t N_BE[256] = {
    0x7e,0xa3,0x72,0xa4, 0xd0,0xdb,0xa1,0xa3,
    0x20,0x48,0x89,0x4d, 0xc7,0x99,0x97,0xa1,
    0x0b,0x84,0x2a,0x9d, 0xb1,0x5f,0xc5,0x61,
    0x4b,0xe5,0xa5,0x73, 0xba,0xcc,0x72,0xa9,
    0x88,0x0a,0x57,0x98, 0xa3,0x87,0x53,0x9b,
    0x7a,0x4c,0x1c,0x71, 0xb6,0xb1,0x3a,0x84,
    0xdb,0xad,0xaf,0x9b, 0x03,0xf7,0x6f,0x32,
    0x70,0x84,0x49,0xc4, 0xfd,0x27,0xd2,0xc4,
    0xaf,0xc9,0xdc,0x46, 0xc4,0xa6,0xbe,0xc5,
    0x5e,0x3a,0x3d,0xb1, 0xa9,0xa2,0x56,0xaf,
    0x05,0x39,0xed,0x2a, 0xb4,0x48,0xb8,0x53,
    0xb0,0xc1,0xaf,0x20, 0x7b,0x6e,0xa2,0x94,
    0x06,0x34,0x91,0xfb, 0x5e,0xb2,0xdc,0x95,
    0x0e,0x8e,0x1e,0x87, 0x19,0xc4,0xe5,0x3c,
    0x06,0xdd,0x3e,0x7a, 0x36,0x4b,0x44,0x65,
    0x26,0x81,0x7d,0xd5, 0x37,0x3d,0x00,0xd6,
    0x71,0x67,0x59,0x06, 0x93,0x4d,0xad,0x0f,
    0x7f,0x6c,0xed,0xda, 0x65,0xb4,0x33,0x68,
    0xf8,0x3b,0xae,0x26, 0xda,0xc4,0x84,0xf0,
    0x00,0x31,0x8d,0xbb, 0x74,0x80,0x22,0x5c,
    0xe6,0x0e,0xbf,0x3a, 0x75,0xec,0xa3,0x65,
    0x6f,0xc5,0xa0,0x85, 0xf0,0xf3,0x4e,0xcf,
    0xa9,0xcb,0x72,0x1b, 0xdb,0xd8,0xea,0x37,
    0xb1,0xd8,0x63,0x42, 0x2c,0x62,0x8c,0x73,
    0x38,0x5d,0x90,0x65, 0x4a,0xa1,0xd0,0x7b,
    0x1a,0x59,0xf6,0x23, 0x42,0x94,0x0b,0xb4,
    0x8f,0xb0,0x5b,0x31, 0x47,0xc9,0x4c,0x57,
    0xd7,0x90,0xae,0xc7, 0x49,0x93,0x3a,0x2a,
    0x19,0xfe,0xc9,0x95, 0x45,0x37,0x6e,0x87,
    0x68,0x16,0xeb,0x2a, 0x76,0xac,0x56,0x9d,
    0x08,0xd8,0xe1,0xfe, 0x51,0x81,0xdf,0xfb,
    0x97,0x52,0xb5,0xfc, 0xe1,0xe9
};

/* ────────────────────────────────────────────────────────────────────────
 * Module-level precomputed Montgomery state (init once, reused for all calls).
 * ──────────────────────────────────────────────────────────────────────── */
static bn_t     g_n;        /* modulus N as little-endian limbs              */
static bn_t     g_r2n;      /* R² mod N = 2^4096 mod N, for to-Montgomery   */
static uint32_t g_n0;       /* -N⁻¹ mod 2^32 (Montgomery constant)          */
static int      g_init = 0; /* 0 = not yet initialised                       */

/* ────────────────────────────────────────────────────────────────────────
 * Big-integer helper functions
 * ──────────────────────────────────────────────────────────────────────── */

/* Compare two NLIMBS-limb integers.
 * Returns positive if a > b, negative if a < b, 0 if equal. */
static int bn_cmp(const bn_t a, const bn_t b)
{
    for (int i = NLIMBS - 1; i >= 0; i--) {
        if (a[i] > b[i]) return  1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/* Subtract in-place: a -= b.  Caller guarantees a >= b. */
static void bn_sub(bn_t a, const bn_t b)
{
    uint64_t borrow = 0;
    for (int i = 0; i < NLIMBS; i++) {
        uint64_t t = (uint64_t)a[i] - b[i] - borrow;
        a[i]   = (uint32_t)t;
        borrow = (t >> 63) & 1u;
    }
}

/* Load 256 big-endian bytes into a little-endian 32-bit-limb array.
 * limb[0] = least-significant word = BE bytes [252..255]. */
static void bn_from_be(const uint8_t src[256], bn_t dst)
{
    for (int i = 0; i < NLIMBS; i++) {
        int off = 252 - 4 * i;   /* byte offset of this limb's MSB */
        dst[i] = ((uint32_t)src[off    ] << 24)
               | ((uint32_t)src[off + 1] << 16)
               | ((uint32_t)src[off + 2] <<  8)
               |  (uint32_t)src[off + 3];
    }
}

/* Store little-endian limbs as 256 big-endian bytes. */
static void bn_to_be(const bn_t src, uint8_t dst[256])
{
    for (int i = 0; i < NLIMBS; i++) {
        int off = 252 - 4 * i;
        dst[off    ] = (uint8_t)(src[i] >> 24);
        dst[off + 1] = (uint8_t)(src[i] >> 16);
        dst[off + 2] = (uint8_t)(src[i] >>  8);
        dst[off + 3] = (uint8_t)(src[i]      );
    }
}

/* ────────────────────────────────────────────────────────────────────────
 * Montgomery multiplication
 *
 * mont_mul(a, b, n, n0, result):
 *   result = a * b * R^{-1}  mod n
 *   where R = 2^(32 * NLIMBS) = 2^2048
 *   n0 = -n[0]^{-1} mod 2^32
 *
 * Uses schoolbook multiplication + REDC (Barrett-Montgomery reduction).
 * Scratch buffer is 130 limbs to safely absorb carry overflow.
 * ──────────────────────────────────────────────────────────────────────── */
static void mont_mul(const bn_t a, const bn_t b,
                     const bn_t n, uint32_t n0, bn_t result)
{
    uint32_t T[2 * NLIMBS + 2];   /* 130 limbs — extra 2 absorb REDC carry overflow */
    memset(T, 0, sizeof(T));

    /* ── Phase 1: T = a * b  (schoolbook, 64×64 → 128 limbs) ─────────── */
    for (int i = 0; i < NLIMBS; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < NLIMBS; j++) {
            uint64_t t = (uint64_t)a[i] * b[j] + T[i + j] + carry;
            T[i + j]   = (uint32_t)t;
            carry      = t >> 32;
        }
        for (int k = i + NLIMBS; carry; k++) {
            uint64_t t = (uint64_t)T[k] + carry;
            T[k]  = (uint32_t)t;
            carry = t >> 32;
        }
    }

    /* ── Phase 2: REDC — eliminate low NLIMBS limbs via multiples of n ── */
    for (int i = 0; i < NLIMBS; i++) {
        /* u chosen so that T[i] + u*n[0] ≡ 0 (mod 2^32) */
        uint32_t u  = T[i] * n0;
        uint64_t carry = 0;
        for (int j = 0; j < NLIMBS; j++) {
            uint64_t t = (uint64_t)u * n[j] + T[i + j] + carry;
            T[i + j]   = (uint32_t)t;
            carry      = t >> 32;
        }
        for (int k = i + NLIMBS; carry; k++) {
            uint64_t t = (uint64_t)T[k] + carry;
            T[k]  = (uint32_t)t;
            carry = t >> 32;
        }
    }

    /* ── Result is in T[NLIMBS..2*NLIMBS-1]; bring to [0, n) ─────────── */
    memcpy(result, T + NLIMBS, NLIMBS * sizeof(uint32_t));
    if (bn_cmp(result, n) >= 0)
        bn_sub(result, n);
}

/* ────────────────────────────────────────────────────────────────────────
 * One-time initialisation of Montgomery parameters
 * ──────────────────────────────────────────────────────────────────────── */

/*
 * pow2_mod: compute result = 2^k mod n via k doublings with conditional subtract.
 * Used for R² = 2^4096 mod N (only 4096 iterations, each O(NLIMBS) — fast).
 * Invariant: result ∈ [0, n) throughout.
 */
static void pow2_mod(int k, const bn_t n, bn_t result)
{
    memset(result, 0, sizeof(bn_t));
    result[0] = 1;  /* start with 2^0 = 1 */

    for (int iter = 0; iter < k; iter++) {
        /* Left-shift result by 1 (multiply by 2). */
        /* Since result < n < 2^2047, we have 2*result < 2^2048, so no 65th limb. */
        uint32_t carry = 0;
        for (int i = 0; i < NLIMBS; i++) {
            uint32_t next = result[i] >> 31;
            result[i]     = (result[i] << 1) | carry;
            carry         = next;
        }
        /* carry is always 0 here (result < 2^2047).  A defensive check is harmless. */
        if (carry || bn_cmp(result, n) >= 0)
            bn_sub(result, n);
    }
}

/*
 * Initialise global Montgomery state from the hardcoded modulus.
 * Not thread-safe; the caller (makwa_hash) uses a simple check-once guard.
 */
static void makwa_init_params(void)
{
    if (g_init) return;

    /* Load N into little-endian limbs */
    bn_from_be(N_BE, g_n);

    /* Compute n0 = -N⁻¹ mod 2^32 via Hensel lifting (Newton iteration mod 2^32).
     * Each iteration doubles precision: 1 → 2 → 4 → 8 → 16 → 32 bits.
     * Starting value x=1 is correct since N is odd so N ≡ 1 (mod 2). */
    uint32_t x = 1;
    for (int i = 0; i < 5; i++)
        x *= 2u - g_n[0] * x;  /* x converges to N[0]^{-1} mod 2^32 */
    g_n0 = (uint32_t)(0u - x); /* negate → g_n0 = -N^{-1} mod 2^32 */

    /* Compute R² mod N = 2^4096 mod N */
    pow2_mod(4096, g_n, g_r2n);

    g_init = 1;
}

/* ────────────────────────────────────────────────────────────────────────
 * Public API
 * ──────────────────────────────────────────────────────────────────────── */

int makwa_hash(const uint8_t *password, size_t passlen,
               const uint8_t *salt,     size_t saltlen,
               uint32_t work_factor,
               uint8_t *out,            size_t outlen)
{
    if (!password || !salt || !out || outlen == 0) return -1;

    /* Lazy initialisation of Montgomery params */
    makwa_init_params();

    /* ── Step 1: Pre-hash → 256 bytes ────────────────────────────────── */
    uint8_t x_bytes[256];
    {
        SHA256_CTX ctx;
        uint8_t    ctr[4];
        for (int i = 0; i < 8; i++) {
            ctr[0] = (uint8_t)(i >> 24);
            ctr[1] = (uint8_t)(i >> 16);
            ctr[2] = (uint8_t)(i >>  8);
            ctr[3] = (uint8_t) i;
            sha256_init(&ctx);
            sha256_update(&ctx, ctr, 4);
            if (passlen) sha256_update(&ctx, password, passlen);
            if (saltlen) sha256_update(&ctx, salt, saltlen);
            sha256_final(&ctx, x_bytes + i * 32);
        }
        /* Clear top byte: ensures x < 2^2040 < N (N > 2^2046).
         * This avoids the need for a full modular reduction of the pre-hash. */
        x_bytes[0] = 0;
    }

    /* ── Step 2: Load pre-hash as little-endian 2048-bit limbs ──────── */
    bn_t x;
    bn_from_be(x_bytes, x);

    /* ── Step 3: Convert to Montgomery form: x_M = x * R mod N ──────── */
    bn_t x_M;
    mont_mul(x, g_r2n, g_n, g_n0, x_M);

    /* ── Step 4: Square work_factor times in Montgomery domain ───────── */
    for (uint32_t i = 0; i < work_factor; i++)
        mont_mul(x_M, x_M, g_n, g_n0, x_M);

    /* ── Step 5: Convert back from Montgomery form: x = x_M * R⁻¹ mod N */
    bn_t one;
    memset(one, 0, sizeof(one));
    one[0] = 1;
    mont_mul(x_M, one, g_n, g_n0, x);

    /* ── Step 6: Post-hash: SHA-256(x_bytes || salt) ─────────────────── */
    bn_to_be(x, x_bytes);
    {
        SHA256_CTX ctx;
        uint8_t    hash[32];
        sha256_init(&ctx);
        sha256_update(&ctx, x_bytes, 256);
        if (saltlen) sha256_update(&ctx, salt, saltlen);
        sha256_final(&ctx, hash);
        size_t copy = outlen < 32u ? outlen : 32u;
        memcpy(out, hash, copy);
        secure_zero(hash, sizeof(hash));
    }

    /* Scrub sensitive intermediates */
    secure_zero(x_bytes, sizeof(x_bytes));
    secure_zero(x,       sizeof(x));
    secure_zero(x_M,     sizeof(x_M));

    return 0;
}
