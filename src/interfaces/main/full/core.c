/**
 * @file core.c
 * @brief Layer 3: Core utility dispatcher (full build)
 * @layer main
 * @category core
 *
 * Provides the simplified high-level API:
 *   nextssl_random      → OS RNG (rng_fill)
 *   nextssl_derive_key  → HKDF-SHA256
 *   nextssl_encrypt     → AES-256-GCM with auto-nonce (same format as aead.c)
 *   nextssl_decrypt     → AES-256-GCM
 *   nextssl_mac         → HMAC-SHA256
 *   nextssl_mac_verify  → HMAC-SHA256 constant-time verify
 *   nextssl_secure_zero → volatile byte-by-byte zeroing
 *   nextssl_constant_compare → constant-time XOR comparison
 */

#include "core.h"
#include "../../core/aead/aead.h"
#include "../../core/kdf/kdf.h"
#include "../../core/mac/mac.h"
#include "../../../seed/rng/rng.h"
#include <string.h>
#include <stdint.h>

#define NONCE_LEN 12
#define TAG_LEN   16
#define OVERHEAD  (NONCE_LEN + TAG_LEN)

/* ========== Random ========== */

NEXTSSL_MAIN_API int nextssl_random(
    uint8_t *output,
    size_t length)
{
    if (!output || length == 0) return -1;
    return rng_fill(output, length);
}

/* ========== Key derivation (HKDF-SHA256) ========== */

NEXTSSL_MAIN_API int nextssl_derive_key(
    const uint8_t *input_key, size_t input_len,
    const char *context,
    uint8_t *output_key, size_t output_len)
{
    if (!input_key || !output_key || output_len == 0) return -1;
    return NEXTSSL_CORE_KDF_H_AGGREGATEkdf_sha256(
        input_key, input_len,
        NULL, 0,
        (const uint8_t *)context, context ? strlen(context) : 0,
        output_key, output_len);
}

/* ========== Authenticated encryption (AES-256-GCM) ========== */

NEXTSSL_MAIN_API int nextssl_encrypt(
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

NEXTSSL_MAIN_API int nextssl_decrypt(
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

/* ========== Message authentication (HMAC-SHA256) ========== */

NEXTSSL_MAIN_API int nextssl_mac(
    const uint8_t *key, size_t key_len,
    const uint8_t *message, size_t message_len,
    uint8_t mac[32])
{
    if (!key || !message || !mac) return -1;
    return NEXTSSL_CORE_MAC_H_AGGREGATEmac_sha256(key, key_len, message, message_len, mac);
}

NEXTSSL_MAIN_API int nextssl_mac_verify(
    const uint8_t *key, size_t key_len,
    const uint8_t *message, size_t message_len,
    const uint8_t mac[32])
{
    if (!key || !message || !mac) return -1;
    return NEXTSSL_CORE_MAC_H_AGGREGATEmac_sha256_verify(key, key_len, message, message_len, mac);
}

/* ========== Secure memory ========== */

NEXTSSL_MAIN_API void nextssl_secure_zero(
    void *data,
    size_t length)
{
    if (!data || length == 0) return;
    volatile uint8_t *p = (volatile uint8_t *)data;
    while (length--) *p++ = 0;
}

NEXTSSL_MAIN_API int nextssl_constant_compare(
    const void *a,
    const void *b,
    size_t length)
{
    if (!a || !b) return 0;
    const uint8_t *pa = (const uint8_t *)a;
    const uint8_t *pb = (const uint8_t *)b;
    uint8_t diff = 0;
    for (size_t i = 0; i < length; i++) diff |= pa[i] ^ pb[i];
    return (diff == 0) ? 1 : 0;
}
