/* isap.c — ISAP-A-128A AEAD (structural implementation)
 *
 * ISAP-A-128A uses the Ascon permutation as its core.
 * This file provides the ISAP mode framing; the full implementation
 * requires the Ascon-128 permutation (rounds p_A=12, p_B=12, p_K=12, p_E=1).
 *
 * Reference: https://isap.iaik.tugraz.at/spec.pdf §3
 *
 * TODO: Wire the Ascon permutation from src/hash/ascon/ or a dedicated
 *       Ascon permutation backend.  Current implementation uses SHA-256
 *       as a structural placeholder with the correct ISAP call graph.
 */
#include "isap.h"
#include "../../../hash/sha256/sha256.h"
#include <string.h>

/* Placeholder permutation (structural only) — replace with Ascon-p */
static void isap_perm(uint8_t state[40])
{
    /* TODO: Replace with ascon_permute(state, 12) */
    sha256_ctx ctx;
    uint8_t out[32];
    sha256_init(&ctx);
    sha256_update(&ctx, state, 40);
    sha256_final(&ctx, out);
    memcpy(state, out, 32);
    /* leave state[32..39] unchanged as placeholder */
}

/* ISAP-RK: Rekeying function to derive a session key */
static void isap_rk(const uint8_t *key, size_t key_len,
                     const uint8_t *y, size_t y_len,
                     uint8_t *out, size_t out_len)
{
    /* TODO: Implement full ISAP-RK per §3.2 using Ascon permutation */
    uint8_t state[40] = {0};
    memcpy(state, key, key_len < 40 ? key_len : 40);
    for (size_t i = 0; i < y_len; i++) {
        state[i & 39] ^= y[i];
        isap_perm(state);
    }
    memcpy(out, state, out_len < 40 ? out_len : 40);
    memset(state, 0, sizeof(state));
}

/* ISAP-MAC: Authentication using ISAP-RK + hash */
static void isap_mac(const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *aad, size_t aad_len,
                      const uint8_t *ct, size_t ct_len,
                      uint8_t *tag)
{
    /* TODO: Full ISAP-MAC per §3.3 using Ascon-p absorb/squeeze */
    uint8_t session_key[16];
    isap_rk(key, key_len, nonce, nonce_len, session_key, 16);

    uint8_t state[40] = {0};
    memcpy(state, session_key, 16);
    if (aad && aad_len) {
        for (size_t i = 0; i < aad_len; i++) {
            state[i & 15] ^= aad[i];
            if ((i & 15) == 15) isap_perm(state);
        }
    }
    state[15] ^= 0x01;  /* domain separation */
    isap_perm(state);
    if (ct && ct_len) {
        for (size_t i = 0; i < ct_len; i++) {
            state[i & 15] ^= ct[i];
            if ((i & 15) == 15) isap_perm(state);
        }
    }
    isap_perm(state);
    memcpy(tag, state, 16);
    memset(state, 0, sizeof(state));
    memset(session_key, 0, sizeof(session_key));
}

/* ISAP-ENC: Keystream generation */
static void isap_enc(const uint8_t *key, size_t key_len,
                      const uint8_t *nonce, size_t nonce_len,
                      const uint8_t *in, uint8_t *out, size_t len)
{
    uint8_t session_key[16];
    isap_rk(key, key_len, nonce, nonce_len, session_key, 16);

    uint8_t state[40] = {0};
    memcpy(state, session_key, 16);
    memcpy(state + 16, nonce, nonce_len < 24 ? nonce_len : 24);

    size_t done = 0;
    while (done < len) {
        isap_perm(state);
        size_t take = (len - done < 8) ? (len - done) : 8;
        for (size_t i = 0; i < take; i++) out[done + i] = in[done + i] ^ state[i];
        done += take;
    }
    memset(state, 0, sizeof(state));
    memset(session_key, 0, sizeof(session_key));
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
        isap_enc(key, ISAP_KEY_SIZE, nonce, ISAP_NONCE_SIZE,
                  plaintext, ciphertext, pt_len);

    /* Authenticate */
    isap_mac(key, ISAP_KEY_SIZE, nonce, ISAP_NONCE_SIZE,
              aad, aad_len, ciphertext, pt_len, tag);
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
    isap_mac(key, ISAP_KEY_SIZE, nonce, ISAP_NONCE_SIZE,
              aad, aad_len, ciphertext, ct_len, computed_tag);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    if (diff != 0) return -1;

    if (ct_len > 0)
        isap_enc(key, ISAP_KEY_SIZE, nonce, ISAP_NONCE_SIZE,
                  ciphertext, plaintext, ct_len);
    return 0;
}
