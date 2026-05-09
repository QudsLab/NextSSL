/* xchacha20_poly1305.c — XChaCha20-Poly1305 via HChaCha20 subkey derivation */
#include "xchacha20_poly1305.h"
#include "../../symmetric/chacha20/chacha20.h"
#include "../../mac/poly1305/poly1305.h"
#include <string.h>

/* XChaCha20-Poly1305 uses HChaCha20 to derive a subkey, then uses
 * ChaCha20-IETF (12-byte nonce = 0x0000 || nonce[16:24]) for encryption,
 * and Poly1305 for authentication. */

int xchacha20poly1305_encrypt(
        const uint8_t  key[XCHACHA20POLY1305_KEY_SIZE],
        const uint8_t  nonce[XCHACHA20POLY1305_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *plaintext,  size_t pt_len,
        uint8_t       *ciphertext,
        uint8_t        tag[XCHACHA20POLY1305_TAG_SIZE])
{
    if (!key || !nonce || !ciphertext || !tag) return -1;
    if (!plaintext && pt_len) return -1;

    /* Step 1: HChaCha20 to derive subkey from key + nonce[0:16] */
    uint8_t subkey[32];
    chacha20_h(subkey, key, nonce);

    /* Step 2: XChaCha20 encrypt using subkey + nonce[16:24] as the 8-byte
     * DJB nonce (first 8 bytes of the final 12-byte IETF nonce are 0x00*4) */
    uint8_t ietf_nonce[12] = {0, 0, 0, 0};  /* 4 zero bytes + 8 bytes from nonce */
    memcpy(ietf_nonce + 4, nonce + 16, 8);

    /* Encrypt using DJB nonce (8 bytes from nonce[16:24]) with counter=1 */
    chacha20_djb(ciphertext, plaintext, pt_len, subkey, nonce + 16, 1);

    /* Step 3: Poly1305 key from ChaCha20 block 0 */
    uint8_t poly_key[64] = {0};
    chacha20_djb(poly_key, poly_key, 64, subkey, nonce + 16, 0);

    /* Step 4: Compute Poly1305 tag over aad || pad || ct || pad || lengths */
    /* Uses poly1305 with the Poly1305-AEAD construction per RFC 8439 §2.8 */
    poly1305_ctx pctx;
    poly1305_init(&pctx, poly_key);

    if (aad && aad_len) {
        poly1305_update(&pctx, aad, aad_len);
        /* Pad to 16-byte boundary */
        if (aad_len & 15) {
            static const uint8_t ZEROS[16] = {0};
            poly1305_update(&pctx, ZEROS, 16 - (aad_len & 15));
        }
    }
    if (pt_len) {
        poly1305_update(&pctx, ciphertext, pt_len);
        if (pt_len & 15) {
            static const uint8_t ZEROS[16] = {0};
            poly1305_update(&pctx, ZEROS, 16 - (pt_len & 15));
        }
    }
    /* Lengths as 64-bit little-endian */
    uint8_t lengths[16];
    for (int i = 0; i < 8; i++) lengths[i]   = (uint8_t)(aad_len >> (i * 8));
    for (int i = 0; i < 8; i++) lengths[8+i] = (uint8_t)(pt_len  >> (i * 8));
    poly1305_update(&pctx, lengths, 16);
    poly1305_finish(&pctx, tag);

    memset(subkey, 0, 32);
    memset(poly_key, 0, 64);
    (void)ietf_nonce;
    return 0;
}

int xchacha20poly1305_decrypt(
        const uint8_t  key[XCHACHA20POLY1305_KEY_SIZE],
        const uint8_t  nonce[XCHACHA20POLY1305_NONCE_SIZE],
        const uint8_t *aad,        size_t aad_len,
        const uint8_t *ciphertext, size_t ct_len,
        const uint8_t  tag[XCHACHA20POLY1305_TAG_SIZE],
        uint8_t       *plaintext)
{
    if (!key || !nonce || !tag || !plaintext) return -1;
    if (!ciphertext && ct_len) return -1;

    /* Derive subkey */
    uint8_t subkey[32];
    chacha20_h(subkey, key, nonce);

    /* Poly1305 key */
    uint8_t poly_key[64] = {0};
    chacha20_djb(poly_key, poly_key, 64, subkey, nonce + 16, 0);

    /* Verify tag */
    poly1305_ctx pctx;
    poly1305_init(&pctx, poly_key);
    if (aad && aad_len) {
        poly1305_update(&pctx, aad, aad_len);
        if (aad_len & 15) {
            static const uint8_t ZEROS[16] = {0};
            poly1305_update(&pctx, ZEROS, 16 - (aad_len & 15));
        }
    }
    if (ct_len) {
        poly1305_update(&pctx, ciphertext, ct_len);
        if (ct_len & 15) {
            static const uint8_t ZEROS[16] = {0};
            poly1305_update(&pctx, ZEROS, 16 - (ct_len & 15));
        }
    }
    uint8_t lengths[16];
    for (int i = 0; i < 8; i++) lengths[i]   = (uint8_t)(aad_len >> (i * 8));
    for (int i = 0; i < 8; i++) lengths[8+i] = (uint8_t)(ct_len  >> (i * 8));
    poly1305_update(&pctx, lengths, 16);

    uint8_t computed_tag[16];
    poly1305_finish(&pctx, computed_tag);

    /* Constant-time comparison */
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) diff |= computed_tag[i] ^ tag[i];
    if (diff != 0) {
        memset(subkey, 0, 32); memset(poly_key, 0, 64);
        return -1;
    }

    /* Decrypt */
    chacha20_djb(plaintext, ciphertext, ct_len, subkey, nonce + 16, 1);
    memset(subkey, 0, 32); memset(poly_key, 0, 64);
    return 0;
}
