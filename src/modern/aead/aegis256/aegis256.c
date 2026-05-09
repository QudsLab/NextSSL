/* aegis256.c — AEGIS-256 AEAD (draft-irtf-cfrg-aegis-aead §3.2)
 *
 * State: 6 × 128-bit blocks (S0..S5)
 * Processes one 16-byte message block per step.
 * Uses software AES-128 round; AES-NI (AESENC) can be substituted for throughput.
 */
#include "aegis256.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>

typedef struct { uint8_t b[16]; } blk_t;

static void xor16(blk_t *out, const blk_t *a, const blk_t *b)
{
    for (int i = 0; i < 16; i++) out->b[i] = a->b[i] ^ b->b[i];
}

static void aes_rnd(blk_t *out, const blk_t *in, const blk_t *rk)
{
    aes_ecb_encrypt_block(rk->b, 128, in->b, out->b);
}

static const blk_t C0 = {{
    0x00,0x01,0x01,0x02,0x03,0x05,0x08,0x0d,
    0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62
}};
static const blk_t C1 = {{
    0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1,
    0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd
}};

typedef struct { blk_t s[6]; } aegis256_state;

static void aegis256_init(aegis256_state *st,
                           const uint8_t key[32],
                           const uint8_t nonce[32])
{
    blk_t K0, K1, N0, N1;
    memcpy(K0.b, key,       16);
    memcpy(K1.b, key + 16,  16);
    memcpy(N0.b, nonce,     16);
    memcpy(N1.b, nonce + 16,16);

    blk_t K0N0, K1N1;
    xor16(&K0N0, &K0, &N0);
    xor16(&K1N1, &K1, &N1);

    st->s[0] = K0N0;
    st->s[1] = K1N1;
    st->s[2] = C1;
    st->s[3] = C0;
    xor16(&st->s[4], &K0, &C0);
    xor16(&st->s[5], &K1, &C1);

    for (int i = 0; i < 4; i++) {
        blk_t t[6];
        aes_rnd(&t[0], &st->s[5], &st->s[0]); xor16(&t[0], &t[0], &K0);
        aes_rnd(&t[1], &st->s[0], &st->s[1]); xor16(&t[1], &t[1], &K1);
        aes_rnd(&t[2], &st->s[1], &st->s[2]); xor16(&t[2], &t[2], &N0);
        aes_rnd(&t[3], &st->s[2], &st->s[3]); xor16(&t[3], &t[3], &N1);
        aes_rnd(&t[4], &st->s[3], &st->s[4]); xor16(&t[4], &t[4], &K0);
        aes_rnd(&t[5], &st->s[4], &st->s[5]); xor16(&t[5], &t[5], &K1);
        for (int j = 0; j < 6; j++) st->s[j] = t[j];
    }
}

static void aegis256_update(aegis256_state *st, const blk_t *m)
{
    blk_t t[6];
    aes_rnd(&t[0], &st->s[5], &st->s[0]);
    aes_rnd(&t[1], &st->s[0], &st->s[1]);
    aes_rnd(&t[2], &st->s[1], &st->s[2]);
    aes_rnd(&t[3], &st->s[2], &st->s[3]);
    aes_rnd(&t[4], &st->s[3], &st->s[4]);
    aes_rnd(&t[5], &st->s[4], &st->s[5]);
    xor16(&st->s[0], &t[0], m);
    st->s[1]=t[1]; st->s[2]=t[2]; st->s[3]=t[3]; st->s[4]=t[4]; st->s[5]=t[5];
}

static void aegis256_enc(aegis256_state *st, const blk_t *pt, blk_t *ct)
{
    blk_t z, tmp;
    xor16(&z, &st->s[2], &st->s[3]);
    for (int i = 0; i < 16; i++) tmp.b[i] = st->s[0].b[i] & st->s[4].b[i];
    xor16(&z, &z, &tmp);
    xor16(&z, &z, &st->s[5]);
    xor16(ct, pt, &z);
    aegis256_update(st, pt);
}

static void aegis256_dec(aegis256_state *st, const blk_t *ct, blk_t *pt)
{
    blk_t z, tmp;
    xor16(&z, &st->s[2], &st->s[3]);
    for (int i = 0; i < 16; i++) tmp.b[i] = st->s[0].b[i] & st->s[4].b[i];
    xor16(&z, &z, &tmp);
    xor16(&z, &z, &st->s[5]);
    xor16(pt, ct, &z);
    aegis256_update(st, pt);
}

static void finalize256(aegis256_state *st, size_t aad_len, size_t ct_len,
                         uint8_t tag[16])
{
    uint8_t len_buf[16] = {0};
    for (int i = 0; i < 8; i++) len_buf[i]   = (uint8_t)((aad_len * 8) >> (i * 8));
    for (int i = 0; i < 8; i++) len_buf[8+i] = (uint8_t)((ct_len  * 8) >> (i * 8));
    blk_t lb;
    memcpy(lb.b, len_buf, 16);
    xor16(&lb, &lb, &st->s[3]);
    for (int i = 0; i < 7; i++) aegis256_update(st, &lb);

    blk_t tmp;
    memcpy(tmp.b, st->s[0].b, 16);
    for (int j = 1; j < 6; j++) xor16(&tmp, &tmp, &st->s[j]);
    memcpy(tag, tmp.b, 16);
}

int aegis256_encrypt(
        const uint8_t  key[AEGIS256_KEY_SIZE],
        const uint8_t  nonce[AEGIS256_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[AEGIS256_TAG128_SIZE])
{
    if (!key || !nonce || !ciphertext || !tag) return -1;
    aegis256_state st;
    aegis256_init(&st, key, nonce);

    for (size_t i = 0; i + 16 <= aad_len; i += 16) {
        blk_t m; memcpy(m.b, aad + i, 16);
        aegis256_update(&st, &m);
    }
    if (aad_len & 15) {
        blk_t m = {{0}}; memcpy(m.b, aad + (aad_len & ~15), aad_len & 15);
        aegis256_update(&st, &m);
    }

    for (size_t i = 0; i + 16 <= pt_len; i += 16) {
        blk_t pt, ct; memcpy(pt.b, plaintext + i, 16);
        aegis256_enc(&st, &pt, &ct);
        memcpy(ciphertext + i, ct.b, 16);
    }
    if (pt_len & 15) {
        size_t off = pt_len & ~15;
        blk_t pt = {{0}}, ct;
        memcpy(pt.b, plaintext + off, pt_len & 15);
        aegis256_enc(&st, &pt, &ct);
        memcpy(ciphertext + off, ct.b, pt_len & 15);
    }

    finalize256(&st, aad_len, pt_len, tag);
    memset(&st, 0, sizeof(st));
    return 0;
}

int aegis256_decrypt(
        const uint8_t  key[AEGIS256_KEY_SIZE],
        const uint8_t  nonce[AEGIS256_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[AEGIS256_TAG128_SIZE],
        uint8_t       *plaintext)
{
    if (!key || !nonce || !tag || !plaintext) return -1;
    aegis256_state st;
    aegis256_init(&st, key, nonce);

    for (size_t i = 0; i + 16 <= aad_len; i += 16) {
        blk_t m; memcpy(m.b, aad + i, 16);
        aegis256_update(&st, &m);
    }
    if (aad_len & 15) {
        blk_t m = {{0}}; memcpy(m.b, aad + (aad_len & ~15), aad_len & 15);
        aegis256_update(&st, &m);
    }

    for (size_t i = 0; i + 16 <= ct_len; i += 16) {
        blk_t ct, pt; memcpy(ct.b, ciphertext + i, 16);
        aegis256_dec(&st, &ct, &pt);
        memcpy(plaintext + i, pt.b, 16);
    }
    if (ct_len & 15) {
        size_t off = ct_len & ~15;
        blk_t ct = {{0}}, pt;
        memcpy(ct.b, ciphertext + off, ct_len & 15);
        aegis256_dec(&st, &ct, &pt);
        memcpy(plaintext + off, pt.b, ct_len & 15);
    }

    uint8_t computed_tag[16];
    finalize256(&st, aad_len, ct_len, computed_tag);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    memset(&st, 0, sizeof(st));
    if (diff != 0) { memset(plaintext, 0, ct_len); return -1; }
    return 0;
}
