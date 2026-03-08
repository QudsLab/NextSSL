/**
 * @file aead.c
 * @brief Layer 3: AEAD dispatcher (full build)
 * @layer main
 * @category aead
 *
 * Output format for all encrypt functions: [12-byte nonce][ciphertext][16-byte tag]
 * Minimum output buffer size: plaintext_len + 28
 */

#include "aead.h"
#include "../../core/aead/aead.h"
#include "../../../seed/rng/rng.h"
#include <string.h>

#define NONCE_LEN 12
#define TAG_LEN   16
#define OVERHEAD  (NONCE_LEN + TAG_LEN)

/* ========== AES-256-GCM ========== */

NEXTSSL_MAIN_API int nextssl_aead_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len)
{
    if (!key || !plaintext || !ciphertext || !ciphertext_len) return -1;

    uint8_t nonce[NONCE_LEN];
    if (rng_fill(nonce, NONCE_LEN) != 0) return -2;

    uint8_t tag[TAG_LEN];
    int ret = nextssl_base_aead_aes256gcm_encrypt(
        key, nonce, NONCE_LEN, NULL, 0,
        plaintext, plaintext_len,
        ciphertext + NONCE_LEN, tag);
    if (ret != 0) return ret;

    memcpy(ciphertext, nonce, NONCE_LEN);
    memcpy(ciphertext + NONCE_LEN + plaintext_len, tag, TAG_LEN);
    *ciphertext_len = plaintext_len + OVERHEAD;
    return 0;
}

NEXTSSL_MAIN_API int nextssl_aead_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len)
{
    if (!key || !ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len < OVERHEAD) return -1;

    size_t pt_len = ciphertext_len - OVERHEAD;
    const uint8_t *nonce = ciphertext;
    const uint8_t *ct    = ciphertext + NONCE_LEN;
    const uint8_t *tag   = ciphertext + NONCE_LEN + pt_len;

    int ok = nextssl_base_aead_aes256gcm_decrypt(
        key, nonce, NONCE_LEN, NULL, 0,
        ct, pt_len, tag, plaintext);
    if (ok != 1) return -3;

    *plaintext_len = pt_len;
    return 0;
}

/* ========== ChaCha20-Poly1305 ========== */

NEXTSSL_MAIN_API int nextssl_aead_chacha_encrypt(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext, size_t *ciphertext_len)
{
    if (!key || !plaintext || !ciphertext || !ciphertext_len) return -1;

    uint8_t nonce[NONCE_LEN];
    if (rng_fill(nonce, NONCE_LEN) != 0) return -2;

    uint8_t tag[TAG_LEN];
    int ret = nextssl_base_aead_chacha20poly1305_encrypt(
        key, nonce, NULL, 0,
        plaintext, plaintext_len,
        ciphertext + NONCE_LEN, tag);
    if (ret != 0) return ret;

    memcpy(ciphertext, nonce, NONCE_LEN);
    memcpy(ciphertext + NONCE_LEN + plaintext_len, tag, TAG_LEN);
    *ciphertext_len = plaintext_len + OVERHEAD;
    return 0;
}

NEXTSSL_MAIN_API int nextssl_aead_chacha_decrypt(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext, size_t *plaintext_len)
{
    if (!key || !ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len < OVERHEAD) return -1;

    size_t pt_len = ciphertext_len - OVERHEAD;
    const uint8_t *nonce = ciphertext;
    const uint8_t *ct    = ciphertext + NONCE_LEN;
    const uint8_t *tag   = ciphertext + NONCE_LEN + pt_len;

    int ok = nextssl_base_aead_chacha20poly1305_decrypt(
        key, nonce, NULL, 0,
        ct, pt_len, tag, plaintext);
    if (ok != 1) return -3;

    *plaintext_len = pt_len;
    return 0;
}

/* ========== AAD variants ========== */

NEXTSSL_MAIN_API int nextssl_aead_encrypt_with_aad(
    const uint8_t key[32],
    const uint8_t *plaintext, size_t plaintext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *ciphertext, size_t *ciphertext_len)
{
    if (!key || !plaintext || !ciphertext || !ciphertext_len) return -1;

    uint8_t nonce[NONCE_LEN];
    if (rng_fill(nonce, NONCE_LEN) != 0) return -2;

    uint8_t tag[TAG_LEN];
    int ret = nextssl_base_aead_aes256gcm_encrypt(
        key, nonce, NONCE_LEN, aad, aad_len,
        plaintext, plaintext_len,
        ciphertext + NONCE_LEN, tag);
    if (ret != 0) return ret;

    memcpy(ciphertext, nonce, NONCE_LEN);
    memcpy(ciphertext + NONCE_LEN + plaintext_len, tag, TAG_LEN);
    *ciphertext_len = plaintext_len + OVERHEAD;
    return 0;
}

NEXTSSL_MAIN_API int nextssl_aead_decrypt_with_aad(
    const uint8_t key[32],
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t *aad, size_t aad_len,
    uint8_t *plaintext, size_t *plaintext_len)
{
    if (!key || !ciphertext || !plaintext || !plaintext_len) return -1;
    if (ciphertext_len < OVERHEAD) return -1;

    size_t pt_len = ciphertext_len - OVERHEAD;
    const uint8_t *nonce = ciphertext;
    const uint8_t *ct    = ciphertext + NONCE_LEN;
    const uint8_t *tag   = ciphertext + NONCE_LEN + pt_len;

    int ok = nextssl_base_aead_aes256gcm_decrypt(
        key, nonce, NONCE_LEN, aad, aad_len,
        ct, pt_len, tag, plaintext);
    if (ok != 1) return -3;

    *plaintext_len = pt_len;
    return 0;
}
