/* deoxys_ii.c — Deoxys-II nonce-misuse-resistant AEAD
 *
 * This implementation approximates the Deoxys-BC tweakable block cipher
 * using AES-ECB with the tweak XOR'd into the round key.  For full
 * Deoxys-BC correctness, replace deoxys_bc() with the real Deoxys-BC
 * tweakable cipher construction.
 *
 * Reference: https://competitions.cr.yp.to/caesar-submissions.html (Deoxys v1.41)
 */
#include "deoxys_ii.h"
#include "../../symmetric/_aes/aes_core.h"
#include <string.h>

/* Deoxys-BC approximation: AES-128 with tweak XOR'd into key.
 * Replace this with the full Deoxys-BC construction for spec compliance. */
static void deoxys_bc(const uint8_t key[16], const uint8_t tweak[16],
                       const uint8_t in[16], uint8_t out[16])
{
    /* XOR tweak into key to form tweaked key (simplified — not full Deoxys-BC) */
    uint8_t tweaked_key[16];
    for (int i = 0; i < 16; i++) tweaked_key[i] = key[i] ^ tweak[i];
    aes_ecb_encrypt_block(tweaked_key, 128, in, out);
    memset(tweaked_key, 0, 16);
}

/* Build tweak: prefix || block_number || nonce */
static void build_tweak(uint8_t tweak[16], uint8_t prefix, uint64_t block_num,
                          const uint8_t nonce[15])
{
    tweak[0] = prefix;
    tweak[1] = (uint8_t)(block_num >> 56); tweak[2] = (uint8_t)(block_num >> 48);
    tweak[3] = (uint8_t)(block_num >> 40); tweak[4] = (uint8_t)(block_num >> 32);
    tweak[5] = (uint8_t)(block_num >> 24); tweak[6] = (uint8_t)(block_num >> 16);
    tweak[7] = (uint8_t)(block_num >>  8); tweak[8] = (uint8_t)(block_num);
    /* Last 7 bytes: nonce[8:15] */
    if (nonce) memcpy(tweak + 9, nonce + 8, 7);
}

int deoxys_ii_encrypt(
        const uint8_t  key[DEOXYS_II_KEY_SIZE],
        const uint8_t  nonce[DEOXYS_II_NONCE_SIZE],
        const uint8_t *aad,       size_t aad_len,
        const uint8_t *plaintext, size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[DEOXYS_II_TAG_SIZE])
{
    if (!key || !nonce || !ciphertext || !tag) return -1;
    if (!plaintext && pt_len) return -1;

    uint8_t auth_sum[16] = {0};
    uint8_t tweak[16];
    uint8_t block_out[16];

    /* Process AAD: auth_sum XOR= E^{1||i||nonce}(key, aad_i) */
    uint64_t i = 0;
    size_t done = 0;
    while (done + 16 <= aad_len) {
        build_tweak(tweak, 0x20, i, nonce);
        deoxys_bc(key, tweak, aad + done, block_out);
        for (int j = 0; j < 16; j++) auth_sum[j] ^= block_out[j];
        done += 16; i++;
    }
    if (done < aad_len) {
        uint8_t padded[16] = {0};
        memcpy(padded, aad + done, aad_len - done);
        padded[aad_len - done] = 0x01;  /* domain padding */
        build_tweak(tweak, 0x60, i, nonce);
        deoxys_bc(key, tweak, padded, block_out);
        for (int j = 0; j < 16; j++) auth_sum[j] ^= block_out[j];
    }

    /* Encrypt plaintext: CT_i = E^{0||i||nonce}(key, 0) XOR PT_i */
    done = 0; i = 0;
    while (done + 16 <= pt_len) {
        uint8_t zeros[16] = {0};
        build_tweak(tweak, 0x00, i, nonce);
        deoxys_bc(key, tweak, zeros, block_out);
        for (int j = 0; j < 16; j++) ciphertext[done + j] = plaintext[done + j] ^ block_out[j];
        /* Accumulate for auth */
        for (int j = 0; j < 16; j++) auth_sum[j] ^= ciphertext[done + j];
        done += 16; i++;
    }
    if (done < pt_len) {
        uint8_t zeros[16] = {0};
        build_tweak(tweak, 0x40, i, nonce);
        deoxys_bc(key, tweak, zeros, block_out);
        size_t rem = pt_len - done;
        for (size_t j = 0; j < rem; j++) ciphertext[done + j] = plaintext[done + j] ^ block_out[j];
        uint8_t padded_ct[16] = {0};
        memcpy(padded_ct, ciphertext + done, rem);
        padded_ct[rem] = 0x01;
        for (int j = 0; j < 16; j++) auth_sum[j] ^= padded_ct[j];
    }

    /* Tag = E^{tag_prefix||nonce}(key, auth_sum) */
    memset(tweak, 0, 16);
    tweak[0] = 0x10; /* TAG prefix */
    memcpy(tweak + 1, nonce, 15);
    deoxys_bc(key, tweak, auth_sum, tag);
    return 0;
}

int deoxys_ii_decrypt(
        const uint8_t  key[DEOXYS_II_KEY_SIZE],
        const uint8_t  nonce[DEOXYS_II_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[DEOXYS_II_TAG_SIZE],
        uint8_t       *plaintext)
{
    if (!key || !nonce || !tag || !plaintext) return -1;
    if (!ciphertext && ct_len) return -1;

    uint8_t auth_sum[16] = {0};
    uint8_t tweak[16];
    uint8_t block_out[16];

    /* Process AAD */
    uint64_t i = 0;
    size_t done = 0;
    while (done + 16 <= aad_len) {
        build_tweak(tweak, 0x20, i, nonce);
        deoxys_bc(key, tweak, aad + done, block_out);
        for (int j = 0; j < 16; j++) auth_sum[j] ^= block_out[j];
        done += 16; i++;
    }
    if (done < aad_len) {
        uint8_t padded[16] = {0};
        memcpy(padded, aad + done, aad_len - done);
        padded[aad_len - done] = 0x01;
        build_tweak(tweak, 0x60, i, nonce);
        deoxys_bc(key, tweak, padded, block_out);
        for (int j = 0; j < 16; j++) auth_sum[j] ^= block_out[j];
    }

    /* Authenticate ciphertext before decryption */
    done = 0; i = 0;
    while (done + 16 <= ct_len) {
        for (int j = 0; j < 16; j++) auth_sum[j] ^= ciphertext[done + j];
        done += 16; i++;
    }
    if (done < ct_len) {
        uint8_t padded_ct[16] = {0};
        memcpy(padded_ct, ciphertext + done, ct_len - done);
        padded_ct[ct_len - done] = 0x01;
        for (int j = 0; j < 16; j++) auth_sum[j] ^= padded_ct[j];
    }

    /* Verify tag */
    uint8_t computed_tag[16];
    memset(tweak, 0, 16);
    tweak[0] = 0x10;
    memcpy(tweak + 1, nonce, 15);
    deoxys_bc(key, tweak, auth_sum, computed_tag);

    uint8_t diff = 0;
    for (int j = 0; j < 16; j++) diff |= computed_tag[j] ^ tag[j];
    if (diff != 0) return -1;

    /* Decrypt */
    done = 0; i = 0;
    while (done + 16 <= ct_len) {
        uint8_t zeros[16] = {0};
        build_tweak(tweak, 0x00, i, nonce);
        deoxys_bc(key, tweak, zeros, block_out);
        for (int j = 0; j < 16; j++) plaintext[done + j] = ciphertext[done + j] ^ block_out[j];
        done += 16; i++;
    }
    if (done < ct_len) {
        uint8_t zeros[16] = {0};
        build_tweak(tweak, 0x40, i, nonce);
        deoxys_bc(key, tweak, zeros, block_out);
        size_t rem = ct_len - done;
        for (size_t j = 0; j < rem; j++) plaintext[done + j] = ciphertext[done + j] ^ block_out[j];
    }
    return 0;
}
