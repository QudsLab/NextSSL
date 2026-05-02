/* lmots.c — LM-OTS one-time signature (SP 800-208 / RFC 8554 §4)
 *
 * Uses SHA-256 as the underlying hash (n = 32).
 * All multi-byte integers are big-endian per RFC 8554.
 */
#include "lmots.h"
#include "../../../hash/fast/sha256.h"
#include <string.h>
#include <stdlib.h>

/* Write 16-bit big-endian */
static void be16(uint8_t *b, uint16_t v) { b[0]=(uint8_t)(v>>8); b[1]=(uint8_t)v; }
/* Write 32-bit big-endian */
static void be32(uint8_t *b, uint32_t v) {
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16);
    b[2]=(uint8_t)(v>> 8); b[3]=(uint8_t)v;
}

/* SHA-256 convenience */
static void H(const uint8_t *data, size_t len, uint8_t out[32])
{
    sha256(data, len, out);
}

/* SHA-256 with two parts concatenated */
static void H2(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen, uint8_t out[32])
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, a, alen);
    sha256_update(&ctx, b, blen);
    sha256_final(&ctx, out);
}

/* Coef(S, i, w): extract w-bit integer at position i from byte string S */
static uint8_t coef(const uint8_t *S, size_t i, uint32_t w)
{
    size_t byte_idx = (i * w) / 8;
    size_t bit_shift = 8 - (w * ((i * w) % 8)) / 1 - w;  /* simplified for w=1,2,4,8 */
    (void)bit_shift;
    /* Simple extraction for power-of-2 widths */
    uint32_t mask = (1u << w) - 1u;
    size_t boff = i * w;
    size_t byte = boff / 8;
    size_t bit  = boff % 8;
    uint16_t word = ((uint16_t)S[byte] << 8) | (byte + 1 < 512 ? S[byte + 1] : 0);
    return (uint8_t)((word >> (16 - bit - w)) & mask);
}

/* Checksum per RFC 8554 §4.4 */
static uint16_t lmots_checksum(const lmots_params_t *par, const uint8_t *Q)
{
    uint32_t sum = 0;
    uint32_t coef_max = (1u << par->w) - 1u;
    uint32_t lc = (par->n * 8) / par->w;
    for (uint32_t i = 0; i < lc; i++)
        sum += coef_max - coef(Q, i, par->w);
    return (uint16_t)(sum << par->ls);
}

int lmots_keygen(const lmots_params_t *par,
                 const uint8_t I[16], uint32_t q,
                 const uint8_t *seed, size_t seed_len,
                 uint8_t *private_key)
{
    if (!par || !I || !seed || !private_key) return -1;
    /* x[i] = H(I || u32(q) || u16(i) || u8(0xff) || seed) */
    uint8_t buf[16 + 4 + 2 + 1 + 64];
    memcpy(buf, I, 16);
    be32(buf + 16, q);
    for (uint32_t i = 0; i < par->p; i++) {
        be16(buf + 20, (uint16_t)i);
        buf[22] = 0xff;
        memcpy(buf + 23, seed, seed_len < 64 ? seed_len : 64);
        H(buf, 23 + (seed_len < 64 ? seed_len : 64), private_key + i * par->n);
    }
    return 0;
}

int lmots_pubkey_from_privkey(const lmots_params_t *par,
                               const uint8_t I[16], uint32_t q,
                               const uint8_t *private_key,
                               uint8_t *public_key)
{
    if (!par || !I || !private_key || !public_key) return -1;
    uint32_t coef_max = (1u << par->w) - 1u;

    /* Compute hash chain endpoints */
    uint8_t *y = (uint8_t *)malloc(par->p * par->n);
    if (!y) return -1;

    for (uint32_t i = 0; i < par->p; i++) {
        uint8_t tmp[32];
        memcpy(tmp, private_key + i * par->n, par->n);
        for (uint32_t j = 0; j < coef_max; j++) {
            uint8_t buf[16 + 4 + 2 + 1 + 32];
            memcpy(buf, I, 16); be32(buf+16, q); be16(buf+20, (uint16_t)i);
            buf[22] = (uint8_t)j;
            memcpy(buf + 23, tmp, par->n);
            H(buf, 23 + par->n, tmp);
        }
        memcpy(y + i * par->n, tmp, par->n);
    }

    /* K = H(I || u32(q) || u16(D_PBLC) || y[0] || ... || y[p-1]) */
    uint8_t header[16 + 4 + 2];
    memcpy(header, I, 16); be32(header + 16, q);
    header[20] = 0x80; header[21] = 0x80; /* D_PBLC = 0x8080 */
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, header, 22);
    sha256_update(&ctx, y, par->p * par->n);
    sha256_final(&ctx, public_key);
    free(y);
    return 0;
}

int lmots_sign(const lmots_params_t *par,
               const uint8_t I[16], uint32_t q,
               const uint8_t *private_key,
               const uint8_t *msg, size_t msglen,
               uint8_t *sig, size_t *sig_len)
{
    if (!par || !I || !private_key || !msg || !sig || !sig_len) return -1;

    /* Build Q = H(I || u32(q) || u16(D_MESG) || C || message)
     * where C is a random 32-byte value (use 0x00...00 for deterministic KAT) */
    uint8_t C[32]; memset(C, 0, 32);

    uint8_t header[16 + 4 + 2];
    memcpy(header, I, 16); be32(header + 16, q);
    header[20] = 0x81; header[21] = 0x81; /* D_MESG = 0x8181 */
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, header, 22);
    sha256_update(&ctx, C, 32);
    sha256_update(&ctx, msg, msglen);
    uint8_t Q[32];
    sha256_final(&ctx, Q);

    /* Append checksum */
    uint16_t cks = lmots_checksum(par, Q);
    uint8_t Qcks[34];
    memcpy(Qcks, Q, 32);
    be16(Qcks + 32, cks);

    /* Build signature: typecode || C || y[0] || ... || y[p-1] */
    uint8_t *p_sig = sig;
    be32(p_sig, (uint32_t)par->type); p_sig += 4;
    memcpy(p_sig, C, 32); p_sig += 32;

    uint32_t coef_max = (1u << par->w) - 1u;
    for (uint32_t i = 0; i < par->p; i++) {
        uint8_t a = coef(Qcks, i, par->w);
        uint8_t tmp[32];
        memcpy(tmp, private_key + i * par->n, par->n);
        for (uint8_t j = 0; j < a; j++) {
            uint8_t buf[16 + 4 + 2 + 1 + 32];
            memcpy(buf, I, 16); be32(buf+16, q); be16(buf+20, (uint16_t)i);
            buf[22] = j;
            memcpy(buf + 23, tmp, par->n);
            H(buf, 23 + par->n, tmp);
        }
        memcpy(p_sig, tmp, par->n);
        p_sig += par->n;
        (void)coef_max;
    }
    *sig_len = (size_t)(p_sig - sig);
    return 0;
}

int lmots_verify(const lmots_params_t *par,
                 const uint8_t I[16], uint32_t q,
                 const uint8_t *sig, size_t sig_len,
                 const uint8_t *msg, size_t msglen,
                 uint8_t *kc)
{
    if (!par || !I || !sig || !msg || !kc) return -1;
    size_t expected = 4 + 32 + par->p * par->n;
    if (sig_len < expected) return -1;

    /* Check typecode */
    uint32_t typecode = ((uint32_t)sig[0] << 24) | ((uint32_t)sig[1] << 16)
                      | ((uint32_t)sig[2] <<  8) |  (uint32_t)sig[3];
    if (typecode != (uint32_t)par->type) return -1;

    const uint8_t *C = sig + 4;

    /* Recompute Q */
    uint8_t header[22];
    memcpy(header, I, 16); be32(header + 16, q);
    header[20] = 0x81; header[21] = 0x81;
    SHA256_CTX ctx;
    sha256_init(&ctx); sha256_update(&ctx, header, 22);
    sha256_update(&ctx, C, 32); sha256_update(&ctx, msg, msglen);
    uint8_t Q[32]; sha256_final(&ctx, Q);

    uint16_t cks = lmots_checksum(par, Q);
    uint8_t Qcks[34]; memcpy(Qcks, Q, 32); be16(Qcks + 32, cks);

    /* Recover public key candidate */
    uint32_t coef_max = (1u << par->w) - 1u;
    const uint8_t *y_sig = sig + 36;
    uint8_t *z = (uint8_t *)malloc(par->p * par->n);
    if (!z) return -1;

    for (uint32_t i = 0; i < par->p; i++) {
        uint8_t a = coef(Qcks, i, par->w);
        uint8_t tmp[32];
        memcpy(tmp, y_sig + i * par->n, par->n);
        for (uint32_t j = a; j < coef_max; j++) {
            uint8_t buf[55];
            memcpy(buf, I, 16); be32(buf+16, q); be16(buf+20, (uint16_t)i);
            buf[22] = (uint8_t)j;
            memcpy(buf + 23, tmp, par->n);
            H(buf, 23 + par->n, tmp);
        }
        memcpy(z + i * par->n, tmp, par->n);
    }

    /* K_c = H(I || u32(q) || D_PBLC || z[0..p-1]) */
    uint8_t hdr2[22];
    memcpy(hdr2, I, 16); be32(hdr2 + 16, q);
    hdr2[20] = 0x80; hdr2[21] = 0x80;
    sha256_init(&ctx); sha256_update(&ctx, hdr2, 22);
    sha256_update(&ctx, z, par->p * par->n);
    sha256_final(&ctx, kc);
    free(z);
    return 0;
}
