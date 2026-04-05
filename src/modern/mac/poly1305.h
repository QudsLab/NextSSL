/* poly1305.h — Poly1305 one-time MAC (RFC 8439 §2.5)
 *
 * Poly1305 is a one-time authenticator.  It MUST be used with a fresh
 * 32-byte key for EVERY message — reusing the key with different messages
 * is catastrophic.
 *
 * In the ChaCha20-Poly1305 AEAD scheme the key is derived from the
 * keystream block 0 (the first 32 bytes); see RFC 8439 §2.6.
 * For standalone use, generate the key from a CSPRNG or derive it via
 * a KDF.  NEVER use a static/long-term key directly.
 *
 * Both one-shot and streaming interfaces are provided.
 */
#ifndef POLY1305_H
#define POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define POLY1305_KEY_LEN  32u
#define POLY1305_MAC_LEN  16u

/**
 * One-shot Poly1305 MAC computation.
 *
 * @param mac      16-byte output MAC.
 * @param message  Input message.
 * @param msg_len  Length of message in bytes.
 * @param key      32-byte one-time key (must not be reused).
 */
void poly1305(uint8_t        mac[16],
              const uint8_t *message, size_t msg_len,
              const uint8_t  key[32]);

/* ---- Incremental / streaming interface ----------------------------------- */

/** Opaque state.  Size matches monocypher's crypto_poly1305_ctx. */
typedef struct {
    uint8_t  c[16];
    size_t   c_idx;
    uint32_t r[4];
    uint32_t pad[4];
    uint32_t h[5];
} poly1305_ctx;

/**
 * Initialise a streaming Poly1305 context.
 *
 * @param ctx  Uninitialised context (caller-allocated).
 * @param key  32-byte one-time key.
 */
void poly1305_init  (poly1305_ctx *ctx, const uint8_t key[32]);

/**
 * Feed |msg_len| bytes into the running MAC.  May be called 0 or more times.
 */
void poly1305_update(poly1305_ctx *ctx,
                     const uint8_t *message, size_t msg_len);

/**
 * Finalise and produce the 16-byte MAC.  The context is wiped after this call
 * and must not be reused.
 *
 * @param ctx  Context previously initialised with poly1305_init().
 * @param mac  16-byte output buffer.
 */
void poly1305_final (poly1305_ctx *ctx, uint8_t mac[16]);

#ifdef __cplusplus
}
#endif

#endif /* POLY1305_H */
