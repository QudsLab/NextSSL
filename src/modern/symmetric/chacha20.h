/* chacha20.h — ChaCha20 stream cipher (RFC 7539 §2.1)
 *
 * Exposes raw ChaCha20 in three nonce variants:
 *   - DJB:  8-byte nonce, 64-bit counter  (original Bernstein spec)
 *   - IETF: 12-byte nonce, 32-bit counter (RFC 7539 / RFC 8439)
 *   - X:    24-byte nonce, 64-bit counter  (XChaCha20, libsodium / WireGuard)
 *
 * WARNING: ChaCha20 without authentication provides confidentiality only.
 * ALWAYS authenticate (e.g. with Poly1305 or poly1305.h) before trusting
 * the output.  Prefer chacha20_poly1305.h for AEAD use cases.
 *
 * In-place operation (cipher_text == plain_text) is supported.
 * Key must be exactly 32 bytes.
 */
#ifndef CHACHA20_H
#define CHACHA20_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Key length in bytes */
#define CHACHA20_KEY_LEN   32u
/* Block size in bytes (used for counter arithmetic) */
#define CHACHA20_BLOCK_LEN 64u

/**
 * ChaCha20-DJB: 8-byte nonce, 64-bit initial counter.
 *
 * @param cipher_text  Output (may alias plain_text).
 * @param plain_text   Input (may be NULL to generate raw keystream — pass
 *                     a zero-filled buffer of text_size as plain_text instead).
 * @param text_size    Length in bytes.
 * @param key          32-byte secret key.
 * @param nonce        8-byte nonce (must not repeat for the same key).
 * @param ctr          Initial 64-bit block counter (usually 0).
 * @return             Next counter value (useful for multi-call streaming).
 */
uint64_t chacha20_djb(uint8_t       *cipher_text,
                      const uint8_t *plain_text,
                      size_t         text_size,
                      const uint8_t  key[32],
                      const uint8_t  nonce[8],
                      uint64_t       ctr);

/**
 * ChaCha20-IETF: 12-byte nonce, 32-bit initial counter (RFC 7539 / RFC 8439).
 *
 * @param nonce  12-byte nonce (must not repeat for the same key).
 * @param ctr    Initial 32-bit block counter (usually 0).
 * @return       Next counter value.
 */
uint32_t chacha20_ietf(uint8_t       *cipher_text,
                       const uint8_t *plain_text,
                       size_t         text_size,
                       const uint8_t  key[32],
                       const uint8_t  nonce[12],
                       uint32_t       ctr);

/**
 * XChaCha20: 24-byte nonce, 64-bit initial counter.
 * Extends the nonce to 24 bytes via a HChaCha20 subkey derivation step,
 * making random nonce generation safe for large message volumes.
 *
 * @param nonce  24-byte nonce.
 * @param ctr    Initial 64-bit block counter (usually 0).
 * @return       Next counter value.
 */
uint64_t chacha20_x(uint8_t       *cipher_text,
                    const uint8_t *plain_text,
                    size_t         text_size,
                    const uint8_t  key[32],
                    const uint8_t  nonce[24],
                    uint64_t       ctr);

/**
 * HChaCha20: derive a 32-byte subkey from key + first 16 bytes of an
 * XChaCha20 nonce.  Used internally by chacha20_x(); exposed for custom
 * key-derivation schemes.
 *
 * @param out  32-byte output subkey.
 * @param key  32-byte input key.
 * @param in   16-byte nonce prefix.
 */
void chacha20_h(uint8_t out[32],
                const uint8_t key[32],
                const uint8_t in[16]);

#ifdef __cplusplus
}
#endif

#endif /* CHACHA20_H */
