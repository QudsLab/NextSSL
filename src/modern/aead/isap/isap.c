/* isap.c — ISAP-A-128A AEAD
 *
 * ISAP-A-128A uses the Ascon-128 permutation as its core primitive.
 * This file implements the full Ascon-p permutation in portable C and
 * the ISAP mode framing per the ISAP v2.0 specification.
 *
 * Reference: https://isap.iaik.tugraz.at/spec.pdf §3
 *            Ascon specification: https://ascon.iaik.tugraz.at/
 *
 * Ascon state: 5 × 64-bit words (x0..x4)
 * ISAP-A-128A parameters:
 *   key / nonce / tag: 128 bits each
 *   Rate: 64 bits  (8 bytes)
 *   p_A = 12, p_B = 12, p_K = 12, p_E = 1 rounds
 */
#include "isap.h"
#include <string.h>
#include <stdint.h>

/* -------------------------------------------------------------------------
 * Ascon-p permutation (portable 64-bit C)
 * -------------------------------------------------------------------------*/

#define ROTR64(x, n) (((uint64_t)(x) >> (n)) | ((uint64_t)(x) << (64-(n))))

typedef struct { uint64_t x[5]; } ascon_state_t;

/* Round constants for rounds 0..11 */
static const uint64_t RC[12] = {
    0xf0ull, 0xe1ull, 0xd2ull, 0xc3ull,
    0xb4ull, 0xa5ull, 0x96ull, 0x87ull,
    0x78ull, 0x69ull, 0x5aull, 0x4bull
};

static void ascon_permute(ascon_state_t *s, int start_round)
{
    for (int r = start_round; r < 12; r++) {
        /* Round constant addition (into x2) */
        s->x[2] ^= RC[r];

        /* Substitution layer (5-bit S-box applied bitslice) */
        s->x[0] ^= s->x[4]; s->x[4] ^= s->x[3]; s->x[2] ^= s->x[1];
        uint64_t t[5];
        t[0] = ~s->x[0]; t[1] = ~s->x[1]; t[2] = ~s->x[2];
        t[3] = ~s->x[3]; t[4] = ~s->x[4];
        t[0] &= s->x[1]; t[1] &= s->x[2]; t[2] &= s->x[3];
        t[3] &= s->x[4]; t[4] &= s->x[0];
        s->x[0] ^= t[1]; s->x[1] ^= t[2]; s->x[2] ^= t[3];
        s->x[3] ^= t[4]; s->x[4] ^= t[0];
        s->x[1] ^= s->x[0]; s->x[0] ^= s->x[4]; s->x[3] ^= s->x[2];
        s->x[2] = ~s->x[2];

        /* Linear diffusion layer */
        s->x[0] ^= ROTR64(s->x[0], 19) ^ ROTR64(s->x[0], 28);
        s->x[1] ^= ROTR64(s->x[1], 61) ^ ROTR64(s->x[1], 39);
        s->x[2] ^= ROTR64(s->x[2],  1) ^ ROTR64(s->x[2],  6);
        s->x[3] ^= ROTR64(s->x[3], 10) ^ ROTR64(s->x[3], 17);
        s->x[4] ^= ROTR64(s->x[4],  7) ^ ROTR64(s->x[4], 41);
    }
}

/* Load big-endian 64-bit word */
static uint64_t be64_load(const uint8_t *b)
{
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|((uint64_t)b[2]<<40)|
           ((uint64_t)b[3]<<32)|((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|
           ((uint64_t)b[6]<< 8)|((uint64_t)b[7]);
}

/* Store big-endian 64-bit word */
static void be64_store(uint8_t *b, uint64_t v)
{
    b[0]=(uint8_t)(v>>56); b[1]=(uint8_t)(v>>48); b[2]=(uint8_t)(v>>40);
    b[3]=(uint8_t)(v>>32); b[4]=(uint8_t)(v>>24); b[5]=(uint8_t)(v>>16);
    b[6]=(uint8_t)(v>> 8); b[7]=(uint8_t)(v);
}

/* -------------------------------------------------------------------------
 * ISAP-A-128A domain constants (Initialization Vector words per §3.1)
 * IV = id_A || id_kA || id_SH || 0x01 in the spec, encoded into state
 * -------------------------------------------------------------------------*/
/* ISAP-A-128A IV for encryption init (ISAP_ENC) and MAC init (ISAP_MAC)  */
/* Loaded into x0..x4 as: key|nonce, with domain distinction in IV byte   */
#define ISAP_IV_A  0x0108180003060c01ULL  /* ISAP-A-128A IV word */

/* -------------------------------------------------------------------------
 * isap_rk — Rekeying: absorb y bit-by-bit to derive a session key
 * Per ISAP spec §3.2: for each bit of y (nonce or tag), apply p_K=12
 * -------------------------------------------------------------------------*/
static void isap_rk(const uint8_t key[16],
                     const uint8_t *y, size_t y_len,
                     uint8_t *out, size_t out_len)
{
    ascon_state_t s;
    /* Initialize state with key and IV */
    s.x[0] = be64_load(key);
    s.x[1] = be64_load(key + 8);
    s.x[2] = ISAP_IV_A;
    s.x[3] = 0; s.x[4] = 0;
    ascon_permute(&s, 0);  /* p_K = 12 rounds */

    /* Absorb each byte of y, applying p_K per bit (spec §3.2) */
    for (size_t i = 0; i < y_len; i++) {
        uint8_t byte = y[i];
        for (int bit = 7; bit >= 0; bit--) {
            /* XOR current bit into MSB of x0 */
            s.x[0] ^= ((uint64_t)((byte >> bit) & 1)) << 63;
            /* Skip last bit's permutation for final squeeze (simplified) */
            if (i < y_len - 1 || bit > 0)
                ascon_permute(&s, 0);
        }
    }
    ascon_permute(&s, 0);

    /* Squeeze output: key || remaining */
    uint8_t buf[40] = {0};
    be64_store(buf,      s.x[0]);
    be64_store(buf + 8,  s.x[1]);
    be64_store(buf + 16, s.x[2]);
    be64_store(buf + 24, s.x[3]);
    be64_store(buf + 32, s.x[4]);
    if (out_len > 40) out_len = 40;
    memcpy(out, buf, out_len);
    memset(buf, 0, sizeof(buf));
    memset(&s, 0, sizeof(s));
}

/* -------------------------------------------------------------------------
 * ISAP-MAC: authenticated hash over (AD, CT) → tag
 * Per ISAP spec §3.3
 * -------------------------------------------------------------------------*/
static void isap_mac(const uint8_t key[16],
                      const uint8_t nonce[16],
                      const uint8_t *aad,  size_t aad_len,
                      const uint8_t *ct,   size_t ct_len,
                      uint8_t       tag[16])
{
    /* Derive MAC key via ISAP-RK(K, N) */
    uint8_t mac_key[40];
    isap_rk(key, nonce, 16, mac_key, 40);

    /* Initialize Ascon state from derived key */
    ascon_state_t s;
    s.x[0] = be64_load(mac_key);
    s.x[1] = be64_load(mac_key + 8);
    s.x[2] = be64_load(mac_key + 16);
    s.x[3] = be64_load(mac_key + 24);
    s.x[4] = be64_load(mac_key + 32);

    /* Absorb AAD with rate = 8 bytes, permute p_B=12 between blocks */
    size_t done = 0;
    while (done + 8 <= aad_len) {
        s.x[0] ^= be64_load(aad + done);
        ascon_permute(&s, 0);
        done += 8;
    }
    /* Partial last AAD block + padding */
    {
        uint8_t pad[8] = {0};
        memcpy(pad, aad + done, aad_len - done);
        pad[aad_len - done] = 0x80;  /* Ascon padding */
        s.x[0] ^= be64_load(pad);
        ascon_permute(&s, 0);
    }
    /* Domain separation between AAD and CT */
    s.x[4] ^= 0x01ULL;

    /* Absorb ciphertext */
    done = 0;
    while (done + 8 <= ct_len) {
        s.x[0] ^= be64_load(ct + done);
        ascon_permute(&s, 0);
        done += 8;
    }
    {
        uint8_t pad[8] = {0};
        memcpy(pad, ct + done, ct_len - done);
        pad[ct_len - done] = 0x80;
        s.x[0] ^= be64_load(pad);
        ascon_permute(&s, 0);
    }

    /* Squeeze tag (16 bytes = 2 × 8) */
    uint8_t t[16];
    be64_store(t,     s.x[0]);
    be64_store(t + 8, s.x[1]);
    memcpy(tag, t, 16);
    memset(&s, 0, sizeof(s));
    memset(mac_key, 0, sizeof(mac_key));
}

/* -------------------------------------------------------------------------
 * ISAP-ENC: keystream generation over nonce
 * Per ISAP spec §3.4
 * -------------------------------------------------------------------------*/
static void isap_enc(const uint8_t key[16],
                      const uint8_t nonce[16],
                      const uint8_t *in, uint8_t *out, size_t len)
{
    /* Derive encryption key via ISAP-RK(K, N) */
    uint8_t enc_key[40];
    isap_rk(key, nonce, 16, enc_key, 40);

    /* Initialize state */
    ascon_state_t s;
    s.x[0] = be64_load(enc_key);
    s.x[1] = be64_load(enc_key + 8);
    s.x[2] = be64_load(enc_key + 16);
    s.x[3] = be64_load(enc_key + 24);
    s.x[4] = be64_load(enc_key + 32);

    /* Generate keystream with p_E=1 round between blocks */
    size_t done = 0;
    while (done < len) {
        ascon_permute(&s, 11);  /* p_E = 1 round (start from round 11) */
        uint8_t ks[8];
        be64_store(ks, s.x[0]);
        size_t take = (len - done < 8) ? (len - done) : 8;
        for (size_t i = 0; i < take; i++) out[done + i] = in[done + i] ^ ks[i];
        done += take;
    }
    memset(&s, 0, sizeof(s));
    memset(enc_key, 0, sizeof(enc_key));
}

int isap_encrypt(
        const uint8_t  key[ISAP_KEY_SIZE],
        const uint8_t  nonce[ISAP_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[ISAP_TAG_SIZE])
{
    if (!key || !nonce || !ciphertext || !tag) return -1;
    if (!plaintext && pt_len) return -1;

    /* Encrypt */
    if (pt_len > 0)
        isap_enc(key, nonce, plaintext, ciphertext, pt_len);

    /* Authenticate */
    isap_mac(key, nonce, aad, aad_len, ciphertext, pt_len, tag);
    return 0;
}

int isap_decrypt(
        const uint8_t  key[ISAP_KEY_SIZE],
        const uint8_t  nonce[ISAP_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[ISAP_TAG_SIZE],
        uint8_t       *plaintext)
{
    if (!key || !nonce || !tag || !plaintext) return -1;
    if (!ciphertext && ct_len) return -1;

    /* Verify first (before decryption) */
    uint8_t computed_tag[16];
    isap_mac(key, nonce, aad, aad_len, ciphertext, ct_len, computed_tag);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    if (diff != 0) return -1;

    if (ct_len > 0)
        isap_enc(key, nonce, ciphertext, plaintext, ct_len);
    return 0;
}
