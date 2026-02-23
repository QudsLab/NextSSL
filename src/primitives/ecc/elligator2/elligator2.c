#include "elligator2.h"
#include "../ed25519/fe.h"
#include <stddef.h>

/*
    Constants for Elligator 2
*/

static const fe fe_one = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// sqrt(-1)
static const fe sqrtm1 = {
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
};

// A = 486662
static const fe A = {486662, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// A^2
static const fe A2 = {
    12721188, 3529, 0, 0, 0, 0, 0, 0, 0, 0
};

// -sqrt(-1) * 2
static const fe ufactor = {
    -1917299, 15887451, -18755900, -7000830, -24778944,
    544946, -16816446, 4011309, -653372, 10741468
};

/*
    Helpers
*/

static void fe_mul_small(fe h, const fe f, int32_t g) {
    fe g_fe;
    fe_0(g_fe);
    g_fe[0] = g;
    fe_mul(h, f, g_fe);
}

// Helper to load integer in little-endian
static uint32_t load32_le(const uint8_t s[4]) {
    return ((uint32_t)s[0] << 0) |
           ((uint32_t)s[1] << 8) |
           ((uint32_t)s[2] << 16) |
           ((uint32_t)s[3] << 24);
}

static uint32_t load24_le(const uint8_t s[3]) {
    return ((uint32_t)s[0] << 0) |
           ((uint32_t)s[1] << 8) |
           ((uint32_t)s[2] << 16);
}

// Helper macros for fe_frombytes_mask
#define FE_CARRY \
    int64_t c; \
    c = (t0 + ((int64_t)1<<25)) >> 26;  t0 -= c * ((int64_t)1 << 26);  t1 += c; \
    c = (t4 + ((int64_t)1<<25)) >> 26;  t4 -= c * ((int64_t)1 << 26);  t5 += c; \
    c = (t1 + ((int64_t)1<<24)) >> 25;  t1 -= c * ((int64_t)1 << 25);  t2 += c; \
    c = (t5 + ((int64_t)1<<24)) >> 25;  t5 -= c * ((int64_t)1 << 25);  t6 += c; \
    c = (t2 + ((int64_t)1<<25)) >> 26;  t2 -= c * ((int64_t)1 << 26);  t3 += c; \
    c = (t6 + ((int64_t)1<<25)) >> 26;  t6 -= c * ((int64_t)1 << 26);  t7 += c; \
    c = (t3 + ((int64_t)1<<24)) >> 25;  t3 -= c * ((int64_t)1 << 25);  t4 += c; \
    c = (t7 + ((int64_t)1<<24)) >> 25;  t7 -= c * ((int64_t)1 << 25);  t8 += c; \
    c = (t4 + ((int64_t)1<<25)) >> 26;  t4 -= c * ((int64_t)1 << 26);  t5 += c; \
    c = (t8 + ((int64_t)1<<25)) >> 26;  t8 -= c * ((int64_t)1 << 26);  t9 += c; \
    c = (t9 + ((int64_t)1<<24)) >> 25;  t9 -= c * ((int64_t)1 << 25);  t0 += c * 19; \
    c = (t0 + ((int64_t)1<<25)) >> 26;  t0 -= c * ((int64_t)1 << 26);  t1 += c; \
    h[0]=(int32_t)t0;  h[1]=(int32_t)t1;  h[2]=(int32_t)t2;  h[3]=(int32_t)t3;  h[4]=(int32_t)t4; \
    h[5]=(int32_t)t5;  h[6]=(int32_t)t6;  h[7]=(int32_t)t7;  h[8]=(int32_t)t8;  h[9]=(int32_t)t9

static void fe_frombytes_mask(fe h, const uint8_t s[32], unsigned nb_mask) {
    uint32_t mask = 0xffffff >> nb_mask;
    int64_t t0 =  load32_le(s);                    // t0 < 2^32
    int64_t t1 =  load24_le(s +  4) << 6;          // t1 < 2^30
    int64_t t2 =  load24_le(s +  7) << 5;          // t2 < 2^29
    int64_t t3 =  load24_le(s + 10) << 3;          // t3 < 2^27
    int64_t t4 =  load24_le(s + 13) << 2;          // t4 < 2^26
    int64_t t5 =  load32_le(s + 16);               // t5 < 2^32
    int64_t t6 =  load24_le(s + 20) << 7;          // t6 < 2^31
    int64_t t7 =  load24_le(s + 23) << 5;          // t7 < 2^29
    int64_t t8 =  load24_le(s + 26) << 4;          // t8 < 2^28
    int64_t t9 = (load24_le(s + 29) & mask) << 2;  // t9 < 2^25
    FE_CARRY;                                  // Carry precondition OK
}

static void wipe_buffer(void *buf, size_t size) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (size--) *p++ = 0;
}

#define WIPE_BUFFER(buf) wipe_buffer(buf, sizeof(buf))

static int crypto_verify32(const uint8_t *x, const uint8_t *y) {
    uint32_t differentbits = 0;
    for (int i = 0; i < 32; i++) {
        differentbits |= x[i] ^ y[i];
    }
    return (1 & ((differentbits - 1) >> 8)) - 1;
}

static int fe_isequal(const fe f, const fe g) {
    uint8_t fs[32];
    uint8_t gs[32];
    fe_tobytes(fs, f);
    fe_tobytes(gs, g);
    int isdifferent = crypto_verify32(fs, gs);
    WIPE_BUFFER(fs);
    WIPE_BUFFER(gs);
    return 1 + isdifferent; // 1 if equal, 0 if different (crypto_verify32 returns -1 on diff, 0 on equal... wait)
}

// Correct crypto_verify32 return: 0 if equal, -1 if different.
// So if equal (0), return 1. If different (-1), return 0.
// My fe_isequal: 1 + 0 = 1 (equal). 1 + (-1) = 0 (different). Correct.

static int fe_isodd(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    int isodd = s[0] & 1;
    WIPE_BUFFER(s);
    return isodd;
}

// Inverse square root.
// Returns true if x is a square, false otherwise.
// After the call:
//   isr = sqrt(1/x)        if x is a non-zero square.
//   isr = sqrt(sqrt(-1)/x) if x is not a square.
//   isr = 0                if x is zero.
static int invsqrt(fe isr, const fe x) {
    fe t0, t1, t2;
    fe_pow22523(t0, x); // t0 = x^((p-5)/8)

    // quartic = x^((p-1)/4)
    fe quartic;
    fe_sq(quartic, t0);
    fe_mul(quartic, quartic, x);

    fe check;
    fe_0(check);          int z0 = fe_isequal(x, check);
    fe_1(check);          int p1 = fe_isequal(quartic, check);
    fe_neg(check, check); int m1 = fe_isequal(quartic, check);
    fe_neg(check, sqrtm1); int ms = fe_isequal(quartic, check);

    // if quartic == -1 or sqrt(-1)
    // then  isr = x^((p-1)/4) * sqrt(-1)
    // else  isr = x^((p-1)/4)
    fe_mul(isr, t0, sqrtm1);
    fe_cmov(isr, t0, 1 - (m1 | ms)); // fe_cmov is like fe_ccopy but takes 'b' as move-if-true?
    // Ed25519 fe_cmov(f, g, b): if b then f=g.
    // Monocypher fe_ccopy(f, g, b): if b then f=g.
    // So compatible.

    WIPE_BUFFER(t0);
    WIPE_BUFFER(t1); // t1 was used in monocypher but here we used t0 directly from pow22523
    WIPE_BUFFER(t2); // unused
    return p1 | m1 | z0;
}

void elligator2_map(uint8_t curve[32], const uint8_t hidden[32]) {
    fe r, u, t1, t2, t3;
    fe_frombytes_mask(r, hidden, 2); // r is encoded in 254 bits.
    fe_sq(r, r);
    fe_add(t1, r, r);
    fe_add(u, t1, fe_one);
    fe_sq (t2, u);
    fe_mul(t3, A2, t1);
    fe_sub(t3, t3, t2);
    fe_mul_small(t3, t3, 486662); // A
    fe_mul(t1, t2, u);
    fe_mul(t1, t3, t1);
    int is_square = invsqrt(t1, t1);
    fe_mul(u, r, ufactor);
    fe_cmov(u, fe_one, is_square);
    fe_sq (t1, t1);
    fe_mul_small(u, u, 486662); // A
    fe_mul(u, u, t3);
    fe_mul(u, u, t2);
    fe_mul(u, u, t1);
    fe_neg(u, u);
    fe_tobytes(curve, u);

    WIPE_BUFFER(t1);  WIPE_BUFFER(r);
    WIPE_BUFFER(t2);  WIPE_BUFFER(u);
    WIPE_BUFFER(t3);
}

int elligator2_rev(uint8_t hidden[32], const uint8_t public_key[32], uint8_t tweak) {
    fe t1, t2, t3;
    fe_frombytes(t1, public_key);    // t1 = u

    fe_add(t2, t1, A);               // t2 = u + A
    fe_mul(t3, t1, t2);
    fe_mul_small(t3, t3, -2);
    int is_square = invsqrt(t3, t3); // t3 = sqrt(-1 / non_square * u * (u+A))
    if (is_square) {
        // The only variable time bit.
        
        fe_cmov(t1, t2, tweak & 1); // multiply by u if v is positive, (wait, logic check)
        // Monocypher: fe_ccopy(t1, t2, tweak & 1);
        // "multiply by u if v is positive, multiply by u+A otherwise" - Monocypher comment seems inverted or I'm misreading?
        // Code: fe_ccopy(t1, t2, tweak & 1);
        // t1 starts as u. t2 is u+A.
        // If tweak&1 is 1, t1 becomes t2 (u+A).
        // If tweak&1 is 0, t1 stays u.
        // So if tweak&1, we use u+A.
        
        fe_mul(t3, t1, t3);        
        fe_mul_small(t1, t3, 2);
        fe_neg(t2, t3);
        fe_cmov(t3, t2, fe_isodd(t1));
        fe_tobytes(hidden, t3);

        // Pad with two random bits
        hidden[31] |= tweak & 0xc0;
    }

    WIPE_BUFFER(t1);
    WIPE_BUFFER(t2);
    WIPE_BUFFER(t3);
    return is_square - 1; // 0 if success (square), -1 if failure (not square)
    // Monocypher: return is_square - 1; 
    // is_square is 1 (true) or 0 (false).
    // If 1, returns 0 (success).
    // If 0, returns -1 (failure).
}

void elligator2_key_pair(uint8_t hidden[32], uint8_t secret_key[32], uint8_t seed[32]) {
    // Not implemented yet due to dependencies on ChaCha20 and X25519 dirty generation.
    // Placeholder.
}
