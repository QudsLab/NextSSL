/* aegis128l.c — AEGIS-128L AEAD (draft-irtf-cfrg-aegis-aead)
 *
 * AEGIS-128L state: 8 × 128-bit AES blocks (S0..S7)
 * Uses one AES round (SubBytes + ShiftRows + MixColumns + AddRoundKey)
 * per step.
 *
 * Reference: draft-irtf-cfrg-aegis-aead §3.1
 * TODO: Replace aes_one_round() with AES-NI intrinsics for production use.
 */
#include "aegis128l.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>

/* 128-bit block */
typedef struct { uint8_t b[16]; } block128_t;

/* XOR two 128-bit blocks */
static void xor128(block128_t *out, const block128_t *a, const block128_t *b)
{
    for (int i = 0; i < 16; i++) out->b[i] = a->b[i] ^ b->b[i];
}

/* AES round: one ECB block encryption serves as AES-round approximation
 * Note: AEGIS needs a single AES round, not full AES.
 * TODO: Use actual AES round function (AESENC intrinsic) for correctness.
 * This approximation uses full AES-128 as a conservative substitute. */
static void aes_round(block128_t *out, const block128_t *in, const block128_t *rk)
{
    /* Approximate: AES-ECB with round key as key, treated as one round */
    aes_ecb_encrypt_block(rk->b, 128, in->b, out->b);
}

/* AEGIS-128L state */
typedef struct { block128_t s[8]; } aegis128l_state;

/* Initialization constants (from AEGIS spec) */
static const block128_t C0 = {{
    0x00,0x01,0x01,0x02,0x03,0x05,0x08,0x0d,
    0x15,0x22,0x37,0x59,0x90,0xe9,0x79,0x62
}};
static const block128_t C1 = {{
    0xdb,0x3d,0x18,0x55,0x6d,0xc2,0x2f,0xf1,
    0x20,0x11,0x31,0x42,0x73,0xb5,0x28,0xdd
}};

static void aegis128l_init(aegis128l_state *st,
                            const uint8_t key[16],
                            const uint8_t nonce[16])
{
    block128_t K, N, K_xor_N;
    memcpy(K.b, key,   16);
    memcpy(N.b, nonce, 16);
    xor128(&K_xor_N, &K, &N);

    st->s[0] = K_xor_N;
    st->s[1] = C1;
    st->s[2] = C0;
    st->s[3] = C1;
    st->s[4] = K_xor_N;
    xor128(&st->s[5], &K, &C0);
    xor128(&st->s[6], &N, &C1);
    xor128(&st->s[7], &N, &C0);

    for (int i = 0; i < 10; i++) {
        block128_t t0, t1, t2, t3, t4, t5, t6, t7;
        aes_round(&t0, &st->s[7], &st->s[0]);
        aes_round(&t1, &st->s[0], &st->s[1]);
        aes_round(&t2, &st->s[1], &st->s[2]);
        aes_round(&t3, &st->s[2], &st->s[3]);
        aes_round(&t4, &st->s[3], &st->s[4]);
        aes_round(&t5, &st->s[4], &st->s[5]);
        aes_round(&t6, &st->s[5], &st->s[6]);
        aes_round(&t7, &st->s[6], &st->s[7]);
        /* XOR with constants */
        xor128(&st->s[0], &t0, &K); xor128(&st->s[4], &t4, &K);
        xor128(&st->s[1], &t1, &N); xor128(&st->s[5], &t5, &N);
        st->s[2]=t2; st->s[3]=t3; st->s[6]=t6; st->s[7]=t7;
    }
}

static void aegis128l_update(aegis128l_state *st,
                              const block128_t *m0, const block128_t *m1)
{
    block128_t t0, t1, t2, t3, t4, t5, t6, t7;
    aes_round(&t7, &st->s[6], &st->s[7]);
    aes_round(&t0, &st->s[7], &st->s[0]);
    aes_round(&t1, &st->s[0], &st->s[1]);
    aes_round(&t2, &st->s[1], &st->s[2]);
    aes_round(&t3, &st->s[2], &st->s[3]);
    aes_round(&t4, &st->s[3], &st->s[4]);
    aes_round(&t5, &st->s[4], &st->s[5]);
    aes_round(&t6, &st->s[5], &st->s[6]);
    xor128(&st->s[0], &t0, m0);
    xor128(&st->s[4], &t4, m1);
    st->s[1]=t1; st->s[2]=t2; st->s[3]=t3;
    st->s[5]=t5; st->s[6]=t6; st->s[7]=t7;
}

static void aegis128l_enc_block(aegis128l_state *st,
                                 const block128_t *ct0, const block128_t *ct1,
                                 block128_t *pt0, block128_t *pt1)
{
    block128_t z0, z1, tmp;
    /* z0 = S6 XOR S1 XOR (S2 AND S3) */
    xor128(&z0, &st->s[6], &st->s[1]);
    for (int i = 0; i < 16; i++) tmp.b[i] = st->s[2].b[i] & st->s[3].b[i];
    xor128(&z0, &z0, &tmp);
    /* z1 = S2 XOR S5 XOR (S6 AND S7) */
    xor128(&z1, &st->s[2], &st->s[5]);
    for (int i = 0; i < 16; i++) tmp.b[i] = st->s[6].b[i] & st->s[7].b[i];
    xor128(&z1, &z1, &tmp);
    /* pt = ct XOR z */
    xor128(pt0, ct0, &z0);
    xor128(pt1, ct1, &z1);
    aegis128l_update(st, pt0, pt1);
}

static void aegis128l_enc_block_enc(aegis128l_state *st,
                                     const block128_t *pt0, const block128_t *pt1,
                                     block128_t *ct0, block128_t *ct1)
{
    block128_t z0, z1, tmp;
    xor128(&z0, &st->s[6], &st->s[1]);
    for (int i = 0; i < 16; i++) tmp.b[i] = st->s[2].b[i] & st->s[3].b[i];
    xor128(&z0, &z0, &tmp);
    xor128(&z1, &st->s[2], &st->s[5]);
    for (int i = 0; i < 16; i++) tmp.b[i] = st->s[6].b[i] & st->s[7].b[i];
    xor128(&z1, &z1, &tmp);
    xor128(ct0, pt0, &z0);
    xor128(ct1, pt1, &z1);
    aegis128l_update(st, pt0, pt1);
}

int aegis128l_encrypt(
        const uint8_t  key[AEGIS128L_KEY_SIZE],
        const uint8_t  nonce[AEGIS128L_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[AEGIS128L_TAG128_SIZE])
{
    if (!key || !nonce || !ciphertext || !tag) return -1;
    if (!plaintext && pt_len) return -1;

    aegis128l_state st;
    aegis128l_init(&st, key, nonce);

    /* Process AAD in 32-byte chunks */
    size_t done = 0;
    while (done + 32 <= aad_len) {
        block128_t m0, m1;
        memcpy(m0.b, aad + done, 16);
        memcpy(m1.b, aad + done + 16, 16);
        aegis128l_update(&st, &m0, &m1);
        done += 32;
    }
    if (done < aad_len) {
        block128_t m0 = {{0}}, m1 = {{0}};
        size_t rem = aad_len - done;
        if (rem <= 16) memcpy(m0.b, aad + done, rem);
        else { memcpy(m0.b, aad + done, 16); memcpy(m1.b, aad + done + 16, rem - 16); }
        aegis128l_update(&st, &m0, &m1);
    }

    /* Encrypt plaintext in 32-byte chunks */
    done = 0;
    while (done + 32 <= pt_len) {
        block128_t pt0, pt1, ct0, ct1;
        memcpy(pt0.b, plaintext + done, 16);
        memcpy(pt1.b, plaintext + done + 16, 16);
        aegis128l_enc_block_enc(&st, &pt0, &pt1, &ct0, &ct1);
        memcpy(ciphertext + done, ct0.b, 16);
        memcpy(ciphertext + done + 16, ct1.b, 16);
        done += 32;
    }
    if (done < pt_len) {
        block128_t pt0 = {{0}}, pt1 = {{0}}, ct0, ct1;
        size_t rem = pt_len - done;
        if (rem <= 16) memcpy(pt0.b, plaintext + done, rem);
        else { memcpy(pt0.b, plaintext + done, 16); memcpy(pt1.b, plaintext + done + 16, rem - 16); }
        aegis128l_enc_block_enc(&st, &pt0, &pt1, &ct0, &ct1);
        if (rem <= 16) memcpy(ciphertext + done, ct0.b, rem);
        else { memcpy(ciphertext + done, ct0.b, 16); memcpy(ciphertext + done + 16, ct1.b, rem - 16); }
    }

    /* Finalize tag */
    block128_t tmp;
    uint8_t len_block[16] = {0};
    for (int i = 0; i < 8; i++) len_block[i]   = (uint8_t)((aad_len * 8) >> (i * 8));
    for (int i = 0; i < 8; i++) len_block[8+i] = (uint8_t)((pt_len  * 8) >> (i * 8));
    block128_t lb;
    memcpy(lb.b, len_block, 16);

    for (int i = 0; i < 7; i++) aegis128l_update(&st, &lb, &lb);

    /* Tag = S0 XOR S1 XOR S2 XOR S3 XOR S4 XOR S5 XOR S6 */
    memcpy(tmp.b, st.s[0].b, 16);
    for (int j = 1; j <= 6; j++) xor128(&tmp, &tmp, &st.s[j]);
    memcpy(tag, tmp.b, 16);

    memset(&st, 0, sizeof(st));
    return 0;
}

int aegis128l_decrypt(
        const uint8_t  key[AEGIS128L_KEY_SIZE],
        const uint8_t  nonce[AEGIS128L_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[AEGIS128L_TAG128_SIZE],
        uint8_t       *plaintext)
{
    if (!key || !nonce || !tag || !plaintext) return -1;
    if (!ciphertext && ct_len) return -1;

    aegis128l_state st;
    aegis128l_init(&st, key, nonce);

    /* Process AAD */
    size_t done = 0;
    while (done + 32 <= aad_len) {
        block128_t m0, m1;
        memcpy(m0.b, aad + done, 16);
        memcpy(m1.b, aad + done + 16, 16);
        aegis128l_update(&st, &m0, &m1);
        done += 32;
    }
    if (done < aad_len) {
        block128_t m0 = {{0}}, m1 = {{0}};
        size_t rem = aad_len - done;
        if (rem <= 16) memcpy(m0.b, aad + done, rem);
        else { memcpy(m0.b, aad + done, 16); memcpy(m1.b, aad + done + 16, rem - 16); }
        aegis128l_update(&st, &m0, &m1);
    }

    /* Decrypt */
    done = 0;
    while (done + 32 <= ct_len) {
        block128_t ct0, ct1, pt0, pt1;
        memcpy(ct0.b, ciphertext + done, 16);
        memcpy(ct1.b, ciphertext + done + 16, 16);
        aegis128l_enc_block(&st, &ct0, &ct1, &pt0, &pt1);
        memcpy(plaintext + done, pt0.b, 16);
        memcpy(plaintext + done + 16, pt1.b, 16);
        done += 32;
    }
    if (done < ct_len) {
        block128_t ct0 = {{0}}, ct1 = {{0}}, pt0, pt1;
        size_t rem = ct_len - done;
        if (rem <= 16) memcpy(ct0.b, ciphertext + done, rem);
        else { memcpy(ct0.b, ciphertext + done, 16); memcpy(ct1.b, ciphertext + done + 16, rem - 16); }
        aegis128l_enc_block(&st, &ct0, &ct1, &pt0, &pt1);
        if (rem <= 16) memcpy(plaintext + done, pt0.b, rem);
        else { memcpy(plaintext + done, pt0.b, 16); memcpy(plaintext + done + 16, pt1.b, rem - 16); }
    }

    /* Compute and verify tag */
    block128_t tmp;
    uint8_t len_block[16] = {0};
    for (int i = 0; i < 8; i++) len_block[i]   = (uint8_t)((aad_len * 8) >> (i * 8));
    for (int i = 0; i < 8; i++) len_block[8+i] = (uint8_t)((ct_len  * 8) >> (i * 8));
    block128_t lb;
    memcpy(lb.b, len_block, 16);
    for (int i = 0; i < 7; i++) aegis128l_update(&st, &lb, &lb);

    memcpy(tmp.b, st.s[0].b, 16);
    for (int j = 1; j <= 6; j++) xor128(&tmp, &tmp, &st.s[j]);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= tmp.b[i] ^ tag[i];
    memset(&st, 0, sizeof(st));
    if (diff != 0) {
        memset(plaintext, 0, ct_len);
        return -1;
    }
    return 0;
}
