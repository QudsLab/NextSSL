/**
 * @file core/aead/aead.c
 * @brief Layer 2 (base) AEAD aggregate shim — delegates to root layer.
 *
 * Root AEAD layout:  ct = [ciphertext (pt_len bytes)][tag (16 bytes)]
 * Base AEAD layout:  separate ciphertext and tag[16] output parameters
 *
 * The shim bridges this difference using a heap-allocated intermediate
 * buffer rather than a VLA to avoid stack overflows on large payloads.
 *
 * Delegation map:
 *   nextssl_base_aead_aes256gcm_*        → nextssl_root_aead_aesgcm_*
 *   nextssl_base_aead_chacha20poly1305_* → nextssl_root_aead_chacha20_*
 *   nextssl_base_aead_aes256gcmsiv_*     → nextssl_root_aead_aesgcmsiv_*
 *                                          (full build only; lite returns -1)
 */

#include "aead.h"
#include "../../root/core/root_aead.h"
#include <stdlib.h>
#include <string.h>

/* =========================================================================
 * Internal helper: split-tag encrypt bridge
 *   calls a root encrypt function that writes [ct||tag] into one buffer,
 *   then splits into the callers separate ct + tag pointers.
 *
 * root_fn signature: (key[32], nonce[12], aad, aad_len, pt, pt_len, ct_combined)
 * ====================================================================== */

typedef int (*root_enc_fn)(const uint8_t key[32],
                            const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct_combined);

typedef int (*root_dec_fn)(const uint8_t key[32],
                            const uint8_t nonce[12],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct_combined, size_t ct_combined_len,
                            uint8_t *pt);

static int bridge_encrypt(root_enc_fn fn,
                           const uint8_t key[32],
                           const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *plaintext, size_t plaintext_len,
                           uint8_t *ciphertext, uint8_t tag[16])
{
    /* Allocate combined output buffer: pt_len bytes ct + 16 bytes tag */
    uint8_t *combined = (uint8_t *)malloc(plaintext_len + 16);
    if (!combined) return -1;

    int ret = fn(key, nonce, aad, aad_len, plaintext, plaintext_len, combined);
    if (ret == 0) {
        memcpy(ciphertext, combined, plaintext_len);
        memcpy(tag, combined + plaintext_len, 16);
    }

    /* Ciphertext is not secret, but wipe to be tidy */
    memset(combined, 0, plaintext_len + 16);
    free(combined);
    return ret;
}

static int bridge_decrypt(root_dec_fn fn,
                           const uint8_t key[32],
                           const uint8_t nonce[12],
                           const uint8_t *aad, size_t aad_len,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t tag[16],
                           uint8_t *plaintext)
{
    /* Allocate combined input buffer: ct_len bytes + 16 bytes tag */
    uint8_t *combined = (uint8_t *)malloc(ciphertext_len + 16);
    if (!combined) return -1;

    memcpy(combined, ciphertext, ciphertext_len);
    memcpy(combined + ciphertext_len, tag, 16);

    int ret = fn(key, nonce, aad, aad_len,
                 combined, ciphertext_len + 16, plaintext);

    memset(combined, 0, ciphertext_len + 16);
    free(combined);

    /*
     * Root decrypt returns 0 on success, -1 on failure (including tag mismatch).
     * Base declaration returns 1 if authenticated, 0 if auth failed, -ve on error.
     */
    if (ret == 0) return 1;
    /* Wipe any partial plaintext on auth failure — mandatory security step */
    if (plaintext && ciphertext_len > 0)
        memset(plaintext, 0, ciphertext_len);
    return 0;
}

/* =========================================================================
 * AES-256-GCM
 *
 * Base takes variable nonce_len; root requires exactly 12 bytes.
 * Non-12-byte nonces are rejected at this layer.
 * ====================================================================== */

int nextssl_base_aead_aes256gcm_encrypt(
    const uint8_t key[32],
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16])
{
    if (!key || !nonce || nonce_len != 12 || !plaintext || !ciphertext || !tag)
        return -1;
    return bridge_encrypt(nextssl_root_aead_aesgcm_encrypt,
                          key, nonce, aad, aad_len,
                          plaintext, plaintext_len, ciphertext, tag);
}

int nextssl_base_aead_aes256gcm_decrypt(
    const uint8_t key[32],
    const uint8_t *nonce, size_t nonce_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext)
{
    if (!key || !nonce || nonce_len != 12 || !ciphertext || !tag || !plaintext)
        return -1;
    return bridge_decrypt(nextssl_root_aead_aesgcm_decrypt,
                          key, nonce, aad, aad_len,
                          ciphertext, ciphertext_len, tag, plaintext);
}

/* =========================================================================
 * ChaCha20-Poly1305 (nonce is fixed 12 bytes in both root and base)
 * ====================================================================== */

int nextssl_base_aead_chacha20poly1305_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16])
{
    if (!key || !nonce || !plaintext || !ciphertext || !tag) return -1;
    return bridge_encrypt(nextssl_root_aead_chacha20_encrypt,
                          key, nonce, aad, aad_len,
                          plaintext, plaintext_len, ciphertext, tag);
}

int nextssl_base_aead_chacha20poly1305_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext)
{
    if (!key || !nonce || !ciphertext || !tag || !plaintext) return -1;
    return bridge_decrypt(nextssl_root_aead_chacha20_decrypt,
                          key, nonce, aad, aad_len,
                          ciphertext, ciphertext_len, tag, plaintext);
}

/* =========================================================================
 * AES-256-GCM-SIV (full build only)
 * ====================================================================== */

#ifndef NEXTSSL_BUILD_LITE

int nextssl_base_aead_aes256gcmsiv_encrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t tag[16])
{
    if (!key || !nonce || !plaintext || !ciphertext || !tag) return -1;
    return bridge_encrypt(nextssl_root_aead_aesgcmsiv_encrypt,
                          key, nonce, aad, aad_len,
                          plaintext, plaintext_len, ciphertext, tag);
}

int nextssl_base_aead_aes256gcmsiv_decrypt(
    const uint8_t key[32],
    const uint8_t nonce[12],
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    const uint8_t tag[16],
    uint8_t *plaintext)
{
    if (!key || !nonce || !ciphertext || !tag || !plaintext) return -1;
    return bridge_decrypt(nextssl_root_aead_aesgcmsiv_decrypt,
                          key, nonce, aad, aad_len,
                          ciphertext, ciphertext_len, tag, plaintext);
}

#else  /* NEXTSSL_BUILD_LITE */

int nextssl_base_aead_aes256gcmsiv_encrypt(const uint8_t k[32],
    const uint8_t n[12], const uint8_t *aad, size_t al,
    const uint8_t *pt, size_t pl, uint8_t *ct, uint8_t tag[16])
    { (void)k;(void)n;(void)aad;(void)al;(void)pt;(void)pl;(void)ct;(void)tag; return -1; }

int nextssl_base_aead_aes256gcmsiv_decrypt(const uint8_t k[32],
    const uint8_t n[12], const uint8_t *aad, size_t al,
    const uint8_t *ct, size_t cl, const uint8_t tag[16], uint8_t *pt)
    { (void)k;(void)n;(void)aad;(void)al;(void)ct;(void)cl;(void)tag;(void)pt; return -1; }

#endif /* NEXTSSL_BUILD_LITE */
