/* three_des.c — Triple-DES (TDEA) CBC implementation (Plan 201 / Plan 205)
 *
 * DES core: public domain — permutation tables from NIST FIPS 46-3.
 * Triple-DES: EDE mode (K1-encrypt, K2-decrypt, K3-encrypt) per NIST SP 800-67.
 *
 * Security note: 3-DES is deprecated (RFC 7525, NIST SP 800-131Ar2 disallows
 * new use after 2023). This implementation is retained for legacy protocol
 * compatibility testing only. Never use for new designs.
 *
 * Input constraint: len MUST be a multiple of THREE_DES_BLOCK_SIZE (8 bytes).
 * Returns 0 on success, -1 if len is not block-aligned or is zero.
 */
#include "three_des.h"
#include "secure_zero.h"
#include <stdint.h>
#include <string.h>

/* =========================================================================
 * DES S-boxes — standard values from FIPS 46-3
 * ========================================================================= */
static const uint8_t s_sbox[8][64] = {
    /* S1 */
    { 14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
       0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
       4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
      15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 },
    /* S2 */
    { 15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
       3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
       0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
      13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 },
    /* S3 */
    { 10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
      13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
      13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
       1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 },
    /* S4 */
    {  7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
      13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
      10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
       3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14 },
    /* S5 */
    {  2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
      14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
       4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
      11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 },
    /* S6 */
    { 12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
      10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
       9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
       4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 },
    /* S7 */
    {  4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
      13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
       1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
       6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 },
    /* S8 */
    { 13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
       1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
       7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
       2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 }
};

/* IP — Initial Permutation (bit positions, 1-indexed, MSB first) */
static const uint8_t s_ip[64] = {
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7
};

/* IP-1 — Inverse Initial Permutation */
static const uint8_t s_iip[64] = {
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25
};

/* E — Expansion permutation for Feistel R half (32 → 48 bits) */
static const uint8_t s_e[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

/* P — P-permutation after S-boxes (32 → 32 bits) */
static const uint8_t s_p[32] = {
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25
};

/* PC-1 — Permuted Choice 1 for key schedule (64 → 56 bits) */
static const uint8_t s_pc1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

/* PC-2 — Permuted Choice 2 for key schedule (56 → 48 bits) */
static const uint8_t s_pc2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

/* Key schedule rotation amounts per round */
static const uint8_t s_rot[16] = {
    1, 1, 2, 2, 2, 2, 2, 2,  1, 2, 2, 2, 2, 2, 2, 1
};

/* =========================================================================
 * Bit manipulation helpers
 * ========================================================================= */

/* Extract bit 'pos' (1-indexed, MSB=1) from 64-bit value stored in 8 bytes */
static inline int bit_get64(const uint8_t b[8], int pos) {
    int byte_idx = (pos - 1) / 8;
    int bit_idx  = 7 - (pos - 1) % 8;
    return (b[byte_idx] >> bit_idx) & 1;
}

/* Set bit 'pos' (1-indexed, MSB=1) in 64-bit value stored in 8 bytes */
static inline void bit_set64(uint8_t b[8], int pos) {
    int byte_idx = (pos - 1) / 8;
    int bit_idx  = 7 - (pos - 1) % 8;
    b[byte_idx] |= (uint8_t)(1 << bit_idx);
}

/* Extract bit 'pos' from 56-bit value stored in first 56 bits of 8 bytes */
static inline int bit_get56(const uint8_t b[8], int pos) {
    /* Same layout — just fewer significant bits in byte 7 */
    int byte_idx = (pos - 1) / 8;
    int bit_idx  = 7 - (pos - 1) % 8;
    return (b[byte_idx] >> bit_idx) & 1;
}

static inline void bit_set56(uint8_t b[8], int pos) {
    int byte_idx = (pos - 1) / 8;
    int bit_idx  = 7 - (pos - 1) % 8;
    b[byte_idx] |= (uint8_t)(1 << bit_idx);
}

/* =========================================================================
 * DES key schedule
 * ========================================================================= */

typedef struct {
    uint8_t k[16][6];   /* 16 round keys, 48 bits each (6 bytes) */
} des_ks_t;

static void des_setkey(const uint8_t key[8], des_ks_t *ks) {
    /* C = bits 1-28 of permuted key, D = bits 29-56.
     * Store C in c[0..3] (28 bits, upper nibble of c[3] unused),
     * store D in d[0..3] similarly. */
    uint32_t C = 0, D = 0;
    int i, j;

    /* Apply PC-1 to extract 56-bit permuted key */
    uint8_t kperm[8] = {0};
    for (i = 0; i < 56; i++) {
        if (bit_get64(key, s_pc1[i]))
            bit_set56(kperm, i + 1);
    }

    /* Split into C (bits 1-28) and D (bits 29-56) as 28-bit integers */
    for (i = 0; i < 28; i++) {
        int byte_idx = i / 8;
        int bit_idx  = 7 - i % 8;
        if ((kperm[byte_idx] >> bit_idx) & 1)
            C |= (uint32_t)1 << (27 - i);
    }
    for (i = 0; i < 28; i++) {
        int bit_pos  = i + 28;
        int byte_idx = bit_pos / 8;
        int bit_idx  = 7 - bit_pos % 8;
        if ((kperm[byte_idx] >> bit_idx) & 1)
            D |= (uint32_t)1 << (27 - i);
    }

    /* Generate 16 round keys */
    for (i = 0; i < 16; i++) {
        /* Left-rotate C and D by s_rot[i] */
        for (j = 0; j < s_rot[i]; j++) {
            C = ((C << 1) | (C >> 27)) & 0x0FFFFFFF;
            D = ((D << 1) | (D >> 27)) & 0x0FFFFFFF;
        }

        /* Combine C‖D back into 56-bit kperm for PC-2 */
        memset(kperm, 0, 8);
        for (j = 0; j < 28; j++) {
            if ((C >> (27 - j)) & 1)
                bit_set56(kperm, j + 1);
        }
        for (j = 0; j < 28; j++) {
            if ((D >> (27 - j)) & 1)
                bit_set56(kperm, j + 29);
        }

        /* Apply PC-2 to produce 48-bit round key */
        memset(ks->k[i], 0, 6);
        for (j = 0; j < 48; j++) {
            if (bit_get56(kperm, s_pc2[j])) {
                int byte_idx = j / 8;
                int bit_idx  = 7 - j % 8;
                ks->k[i][byte_idx] |= (uint8_t)(1 << bit_idx);
            }
        }
    }

    secure_zero(&C, sizeof(C));
    secure_zero(&D, sizeof(D));
    secure_zero(kperm, sizeof(kperm));
}

/* =========================================================================
 * DES Feistel function F(R, K)
 * ========================================================================= */
static uint32_t des_f(uint32_t r, const uint8_t k[6]) {
    /* Expand R (32 bits) to 48 bits via E permutation, represented as 6 bytes */
    uint8_t er[6] = {0};
    uint8_t rb[4];  /* R as big-endian bytes */
    rb[0] = (uint8_t)(r >> 24);
    rb[1] = (uint8_t)(r >> 16);
    rb[2] = (uint8_t)(r >>  8);
    rb[3] = (uint8_t)(r);

    uint8_t r8[8] = { rb[0], rb[1], rb[2], rb[3], 0, 0, 0, 0 };
    for (int i = 0; i < 48; i++) {
        if (bit_get64(r8, s_e[i])) {
            int byte_idx = i / 8;
            int bit_idx  = 7 - i % 8;
            er[byte_idx] |= (uint8_t)(1 << bit_idx);
        }
    }

    /* XOR with round key */
    for (int i = 0; i < 6; i++) er[i] ^= k[i];

    /* S-box substitution: 8 groups of 6 bits → 8 groups of 4 bits → 32 bits */
    uint32_t out = 0;
    for (int s = 0; s < 8; s++) {
        int bit_pos = s * 6;
        int byte0 = bit_pos / 8;
        int shift0 = 7 - (bit_pos % 8);

        /* Extract 6 bits — may span two bytes */
        int b0 = (er[byte0] >> shift0) & 1;           /* outermost (row bit 1) */
        /* bits 1-4 (column) */
        /* Extract 6 consecutive bits from the bit stream */
        uint8_t six = 0;
        for (int b = 0; b < 6; b++) {
            int bp = bit_pos + b;
            int by = bp / 8;
            int bi = 7 - bp % 8;
            if ((er[by] >> bi) & 1)
                six |= (uint8_t)(1 << (5 - b));
        }
        (void)b0;

        int row = ((six >> 5) & 1) << 1 | (six & 1);   /* bits 1 and 6 */
        int col = (six >> 1) & 0xF;                     /* bits 2-5 */
        uint8_t sv = s_sbox[s][row * 16 + col];         /* 4-bit output */

        out = (out << 4) | (sv & 0xF);
    }

    /* P permutation */
    uint32_t out_p = 0;
    uint8_t out_b[8] = { (uint8_t)(out >> 24), (uint8_t)(out >> 16),
                          (uint8_t)(out >>  8), (uint8_t)(out), 0, 0, 0, 0 };
    for (int i = 0; i < 32; i++) {
        if (bit_get64(out_b, s_p[i])) {
            out_p |= (uint32_t)1 << (31 - i);
        }
    }

    return out_p;
}

/* =========================================================================
 * DES single-block encrypt/decrypt
 * ========================================================================= */
static void des_block_crypt(const uint8_t in[8], uint8_t out[8],
                             const des_ks_t *ks, int encrypt) {
    uint8_t ip_out[8] = {0};

    /* Initial permutation */
    for (int i = 0; i < 64; i++) {
        if (bit_get64(in, s_ip[i]))
            bit_set64(ip_out, i + 1);
    }

    uint32_t L = ((uint32_t)ip_out[0] << 24) | ((uint32_t)ip_out[1] << 16)
               | ((uint32_t)ip_out[2] <<  8) |  (uint32_t)ip_out[3];
    uint32_t R = ((uint32_t)ip_out[4] << 24) | ((uint32_t)ip_out[5] << 16)
               | ((uint32_t)ip_out[6] <<  8) |  (uint32_t)ip_out[7];

    /* 16 Feistel rounds */
    for (int i = 0; i < 16; i++) {
        int round = encrypt ? i : (15 - i);
        uint32_t tmp = R;
        R = L ^ des_f(R, ks->k[round]);
        L = tmp;
    }

    /* Final permutation (IP^-1), note swap R‖L */
    uint8_t pre_iip[8];
    pre_iip[0] = (uint8_t)(R >> 24); pre_iip[1] = (uint8_t)(R >> 16);
    pre_iip[2] = (uint8_t)(R >>  8); pre_iip[3] = (uint8_t)(R);
    pre_iip[4] = (uint8_t)(L >> 24); pre_iip[5] = (uint8_t)(L >> 16);
    pre_iip[6] = (uint8_t)(L >>  8); pre_iip[7] = (uint8_t)(L);

    memset(out, 0, 8);
    for (int i = 0; i < 64; i++) {
        if (bit_get64(pre_iip, s_iip[i]))
            bit_set64(out, i + 1);
    }
}

/* =========================================================================
 * Triple-DES EDE (K1-enc, K2-dec, K3-enc) key schedule setup
 * ========================================================================= */
typedef struct {
    des_ks_t ks1, ks2, ks3;
} tdes_ctx_t;

static void tdes_init(const uint8_t key[24], tdes_ctx_t *ctx) {
    des_setkey(key,      &ctx->ks1);
    des_setkey(key +  8, &ctx->ks2);
    des_setkey(key + 16, &ctx->ks3);
}

static void tdes_block_encrypt(const uint8_t in[8], uint8_t out[8],
                                const tdes_ctx_t *ctx) {
    uint8_t tmp1[8], tmp2[8];
    des_block_crypt(in,   tmp1, &ctx->ks1, 1);  /* K1 encrypt */
    des_block_crypt(tmp1, tmp2, &ctx->ks2, 0);  /* K2 decrypt */
    des_block_crypt(tmp2, out,  &ctx->ks3, 1);  /* K3 encrypt */
    secure_zero(tmp1, 8);
    secure_zero(tmp2, 8);
}

static void tdes_block_decrypt(const uint8_t in[8], uint8_t out[8],
                                const tdes_ctx_t *ctx) {
    uint8_t tmp1[8], tmp2[8];
    des_block_crypt(in,   tmp1, &ctx->ks3, 0);  /* K3 decrypt */
    des_block_crypt(tmp1, tmp2, &ctx->ks2, 1);  /* K2 encrypt */
    des_block_crypt(tmp2, out,  &ctx->ks1, 0);  /* K1 decrypt */
    secure_zero(tmp1, 8);
    secure_zero(tmp2, 8);
}

/* =========================================================================
 * Public API: CBC encrypt / decrypt
 * ========================================================================= */

int three_des_cbc_encrypt(const uint8_t key[THREE_DES_KEY_SIZE],
                          const uint8_t iv[THREE_DES_BLOCK_SIZE],
                          const uint8_t *plaintext,  size_t len,
                          uint8_t       *ciphertext)
{
    if (!key || !iv || !plaintext || !ciphertext) return -1;
    if (len == 0 || (len % THREE_DES_BLOCK_SIZE) != 0) return -1;

    tdes_ctx_t ctx;
    tdes_init(key, &ctx);

    uint8_t fb[8];
    memcpy(fb, iv, 8);

    for (size_t off = 0; off < len; off += 8) {
        uint8_t xored[8];
        for (int i = 0; i < 8; i++)
            xored[i] = plaintext[off + i] ^ fb[i];
        tdes_block_encrypt(xored, ciphertext + off, &ctx);
        memcpy(fb, ciphertext + off, 8);
        secure_zero(xored, 8);
    }

    secure_zero(&ctx, sizeof(ctx));
    secure_zero(fb, 8);
    return 0;
}

int three_des_cbc_decrypt(const uint8_t key[THREE_DES_KEY_SIZE],
                          const uint8_t iv[THREE_DES_BLOCK_SIZE],
                          const uint8_t *ciphertext, size_t len,
                          uint8_t       *plaintext)
{
    if (!key || !iv || !ciphertext || !plaintext) return -1;
    if (len == 0 || (len % THREE_DES_BLOCK_SIZE) != 0) return -1;

    tdes_ctx_t ctx;
    tdes_init(key, &ctx);

    uint8_t fb[8];
    memcpy(fb, iv, 8);

    for (size_t off = 0; off < len; off += 8) {
        uint8_t decrypted[8];
        tdes_block_decrypt(ciphertext + off, decrypted, &ctx);
        for (int i = 0; i < 8; i++)
            plaintext[off + i] = decrypted[i] ^ fb[i];
        memcpy(fb, ciphertext + off, 8);
        secure_zero(decrypted, 8);
    }

    secure_zero(&ctx, sizeof(ctx));
    secure_zero(fb, 8);
    return 0;
}
