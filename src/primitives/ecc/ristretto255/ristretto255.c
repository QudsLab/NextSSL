#include "ristretto255.h"
#include "../ed25519/fe.h"
#include "../ed25519/ge.h"
#include "../ed25519/sc.h"
#include <string.h>

/* Constants adapted from libsodium's fe_25_5/constants.h */

/* sqrt(-1) */
static const fe fe_sqrtm1 = {
    -32595792, -7943725,  9377950,  3500415, 12389472, -272473, -25146209, -2005654, 326686, 11406482
};

/* 37095705934669439343138083508754565189542113879843219016388785533085940283555 */
static const fe ed25519_d = {
    -10913610, 13857413, -15372611, 6949391,   114729, -8787816, -6275908, -3247719, -18696448, -12055116
};

/* sqrt(ad - 1) with a = -1 (mod p) */
static const fe ed25519_sqrtadm1 = {
    24849947, -153582, -23613485, 6347715, -21072328, -667138, -25271143, -15367704, -870347, 14525639
};

/* 1 / sqrt(a - d) */
static const fe ed25519_invsqrtamd = {
    6111485, 4156064, -27798727, 12243468, -25904040, 120897, 20826367, -7060776, 6093568, -1986012
};

/* 1 - d ^ 2 */
static const fe ed25519_onemsqd = {
    6275446, -16617371, -22938544, -3773710, 11667077, 7397348, -27922721, 1766195, -24433858, 672203
};

/* (d - 1) ^ 2 */
static const fe ed25519_sqdmone = {
    15551795, -11097455, -13425098, -10125071, -11896535, 10178284, -26634327, 4729244, -5282110, -10116402
};

/* Helper for fe_abs: |x| = x if x >= 0, -x if x < 0 */
static void fe_abs(fe h) {
    fe neg_h;
    fe_neg(neg_h, h);
    fe_cmov(h, neg_h, fe_isnegative(h));
}

/* Helper wrapper for ge_add to match libsodium usage */
static void ge_p3_add(ge_p3 *r, const ge_p3 *p, const ge_p3 *q) {
    ge_cached q_cached;
    ge_p1p1 p1p1;
    ge_p3_to_cached(&q_cached, q);
    ge_add(&p1p1, p, &q_cached);
    ge_p1p1_to_p3(r, &p1p1);
}

/* Helper wrapper for ge_sub to match libsodium usage */
static void ge_p3_sub(ge_p3 *r, const ge_p3 *p, const ge_p3 *q) {
    ge_cached q_cached;
    ge_p1p1 p1p1;
    ge_p3_to_cached(&q_cached, q);
    ge_sub(&p1p1, p, &q_cached);
    ge_p1p1_to_p3(r, &p1p1);
}

/* Ristretto255 Core Logic */

static int ristretto255_sqrt_ratio_m1(fe x, const fe u, const fe v) {
    fe v3, vxx, m_root_check, p_root_check, f_root_check, x_sqrtm1;
    int has_m_root, has_p_root, has_f_root;

    fe_sq(v3, v);
    fe_mul(v3, v3, v); /* v3 = v^3 */
    fe_sq(x, v3);
    fe_mul(x, x, u);
    fe_mul(x, x, v); /* x = uv^7 */

    fe_pow22523(x, x); /* x = (uv^7)^((q-5)/8) */
    fe_mul(x, x, v3);
    fe_mul(x, x, u); /* x = uv^3(uv^7)^((q-5)/8) */

    fe_sq(vxx, x);
    fe_mul(vxx, vxx, v); /* vx^2 */
    fe_sub(m_root_check, vxx, u); /* vx^2-u */
    fe_add(p_root_check, vxx, u); /* vx^2+u */
    fe_mul(f_root_check, u, fe_sqrtm1); /* u*sqrt(-1) */
    fe_add(f_root_check, vxx, f_root_check); /* vx^2+u*sqrt(-1) */

    has_m_root = fe_isnonzero(m_root_check) == 0;
    has_p_root = fe_isnonzero(p_root_check) == 0;
    has_f_root = fe_isnonzero(f_root_check) == 0;

    fe_mul(x_sqrtm1, x, fe_sqrtm1); /* x*sqrt(-1) */

    fe_cmov(x, x_sqrtm1, has_p_root | has_f_root);
    fe_abs(x);

    return has_m_root | has_p_root;
}

static int ristretto255_is_canonical(const unsigned char *s) {
    unsigned char c, d, e;
    unsigned int i;

    c = (s[31] & 0x7f) ^ 0x7f;
    for (i = 30; i > 0; i--) {
        c |= s[i] ^ 0xff;
    }
    c = (((unsigned int) c) - 1U) >> 8;
    
    d = (0xed - 1U - (unsigned int) s[0]) >> 8;
    e = (s[31] >> 5) & 1;
    
    return 1 - (((c & d) | e | (s[0] & 1)) & 1);
}

static int ristretto255_frombytes(ge_p3 *h, const unsigned char *s) {
    fe inv_sqrt, one, s_, ss, u1, u2, u1u1, u2u2, v, v_u2u2;
    int notsquare;

    if (ristretto255_is_canonical(s) == 0) {
        return -1;
    }

    fe_frombytes(s_, s);
    fe_sq(ss, s_); /* ss = s^2 */

    fe_1(u1);
    fe_sub(u1, u1, ss); /* u1 = 1-ss */
    fe_sq(u1u1, u1); /* u1u1 = u1^2 */

    fe_1(u2);
    fe_add(u2, u2, ss); /* u2 = 1+ss */
    fe_sq(u2u2, u2); /* u2u2 = u2^2 */

    fe_mul(v, ed25519_d, u1u1); /* v = d*u1^2 */
    fe_neg(v, v); /* v = -d*u1^2 */
    fe_sub(v, v, u2u2); /* v = -(d*u1^2)-u2^2 */

    fe_mul(v_u2u2, v, u2u2); /* v_u2u2 = v*u2^2 */

    fe_1(one);
    notsquare = ristretto255_sqrt_ratio_m1(inv_sqrt, one, v_u2u2);
    
    fe_mul(h->X, inv_sqrt, u2);
    fe_mul(h->Y, inv_sqrt, h->X);
    fe_mul(h->Y, h->Y, v);

    fe_mul(h->X, h->X, s_);
    fe_add(h->X, h->X, h->X);
    fe_abs(h->X);
    fe_mul(h->Y, u1, h->Y);
    fe_1(h->Z);
    fe_mul(h->T, h->X, h->Y);

    return - ((1 - notsquare) | fe_isnegative(h->T) | (fe_isnonzero(h->Y) == 0));
}

static void ristretto255_tobytes(unsigned char *s, const ge_p3 *h) {
    fe den1, den2, den_inv, eden, inv_sqrt, ix, iy, one, s_, t_z_inv, u1, u2, u1_u2u2, x_, y_, x_z_inv, z_inv, zmy;
    int rotate;

    fe_add(u1, h->Z, h->Y);
    fe_sub(zmy, h->Z, h->Y);
    fe_mul(u1, u1, zmy);
    fe_mul(u2, h->X, h->Y);

    fe_sq(u1_u2u2, u2);
    fe_mul(u1_u2u2, u1, u1_u2u2);

    fe_1(one);
    (void) ristretto255_sqrt_ratio_m1(inv_sqrt, one, u1_u2u2);
    
    fe_mul(den1, inv_sqrt, u1);
    fe_mul(den2, inv_sqrt, u2);
    fe_mul(z_inv, den1, den2);
    fe_mul(z_inv, z_inv, h->T);

    fe_mul(ix, h->X, fe_sqrtm1);
    fe_mul(iy, h->Y, fe_sqrtm1);
    fe_mul(eden, den1, ed25519_invsqrtamd);

    fe_mul(t_z_inv, h->T, z_inv);
    rotate = fe_isnegative(t_z_inv);

    fe_copy(x_, h->X);
    fe_copy(y_, h->Y);
    fe_copy(den_inv, den2);

    fe_cmov(x_, iy, rotate);
    fe_cmov(y_, ix, rotate);
    fe_cmov(den_inv, eden, rotate);

    fe_mul(x_z_inv, x_, z_inv);
    
    {
        fe neg_y;
        fe_neg(neg_y, y_);
        fe_cmov(y_, neg_y, fe_isnegative(x_z_inv));
    }

    fe_sub(s_, h->Z, y_);
    fe_mul(s_, den_inv, s_);
    fe_abs(s_);
    fe_tobytes(s, s_);
}

/* Public API Implementation */

int ristretto255_is_valid_point(const unsigned char *p) {
    ge_p3 p_p3;
    if (ristretto255_frombytes(&p_p3, p) != 0) {
        return 0;
    }
    return 1;
}

int ristretto255_add(unsigned char *r, const unsigned char *p, const unsigned char *q) {
    ge_p3 p_p3, q_p3, r_p3;

    if (ristretto255_frombytes(&p_p3, p) != 0 ||
        ristretto255_frombytes(&q_p3, q) != 0) {
        return -1;
    }
    ge_p3_add(&r_p3, &p_p3, &q_p3);
    ristretto255_tobytes(r, &r_p3);

    return 0;
}

int ristretto255_sub(unsigned char *r, const unsigned char *p, const unsigned char *q) {
    ge_p3 p_p3, q_p3, r_p3;

    if (ristretto255_frombytes(&p_p3, p) != 0 ||
        ristretto255_frombytes(&q_p3, q) != 0) {
        return -1;
    }
    ge_p3_sub(&r_p3, &p_p3, &q_p3);
    ristretto255_tobytes(r, &r_p3);

    return 0;
}

/* Elligator and From Hash */

static void ristretto255_elligator(ge_p3 *p, const fe t) {
    fe c, n, one, r, rpd, s, s_prime, ss, u, v, w0, w1, w2, w3;
    int wasnt_square;

    fe_1(one);
    fe_sq(r, t);
    fe_mul(r, fe_sqrtm1, r);
    fe_add(u, r, one);
    fe_mul(u, u, ed25519_onemsqd);
    
    fe_1(c); fe_neg(c, c); /* c = -1 */
    fe_add(rpd, r, ed25519_d);
    fe_mul(v, r, ed25519_d);
    fe_sub(v, c, v);
    fe_mul(v, v, rpd);
    
    wasnt_square = 1 - ristretto255_sqrt_ratio_m1(s, u, v);
    fe_mul(s_prime, s, t);
    fe_abs(s_prime);
    fe_neg(s_prime, s_prime);
    fe_cmov(s, s_prime, wasnt_square);
    fe_cmov(c, r, wasnt_square);
    
    fe_sub(n, r, one);
    fe_mul(n, n, c);
    fe_mul(n, n, ed25519_sqdmone);
    fe_sub(n, n, v);
    
    fe_add(w0, s, s);
    fe_mul(w0, w0, v);
    fe_mul(w1, n, ed25519_sqrtadm1);
    fe_sq(ss, s);
    fe_sub(w2, one, ss);
    fe_add(w3, one, ss);
    
    fe_mul(p->X, w0, w3);
    fe_mul(p->Y, w2, w1);
    fe_mul(p->Z, w1, w3);
    fe_mul(p->T, w0, w2);
}

int ristretto255_from_hash(unsigned char *p_out, const unsigned char *r) {
    fe r0, r1;
    ge_p3 p0, p1, p;
    
    /* 64 bytes hash input split into two 32 byte chunks */
    fe_frombytes(r0, r);
    fe_frombytes(r1, r + 32);
    
    ristretto255_elligator(&p0, r0);
    ristretto255_elligator(&p1, r1);
    ge_p3_add(&p, &p0, &p1);
    
    ristretto255_tobytes(p_out, &p);
    return 0;
}
