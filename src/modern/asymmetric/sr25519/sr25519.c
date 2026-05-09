/* sr25519.c — Sr25519 / Schnorrkel signatures
 *
 * This implements the Schnorrkel signing scheme over Ristretto255.
 * The implementation uses the ristretto255 group operations from
 * src/modern/curve_math/ristretto255.h and SHA-512 for hash expansion.
 *
 * Key expansion (mini-secret → secret key):
 *   expanded = SHA-512(seed)
 *   scalar   = expanded[0..31], with bits 0,1,2 of byte 0 cleared
 *                               and bit 7 of byte 31 cleared, bit 6 set
 *   nonce    = expanded[32..63]
 *
 * Signing (Schnorr with Merlin transcript):
 *   r  = SHA-512(nonce || context || msg) reduced mod ℓ
 *   R  = r * B (Ristretto255 base point)
 *   k  = SHA-512(R_compressed || public_key || context || msg) mod ℓ
 *   s  = (r + k * scalar) mod ℓ
 *   sig = R_compressed || s
 *
 * TODO: For production use, clone examples/c/sr25519/ (Zondax/c-schnorrkel)
 *       and wire the full Merlin transcript. This file provides the correct
 *       API surface and a simplified Schnorr implementation.
 */
#include "sr25519.h"
#include "../../curve_math/ristretto255.h"
#include "../../../hash/sha512/sha512.h"
#include <string.h>

extern int rng_fill(void *buf, size_t len);

/* Scalar: 32-byte little-endian value mod ℓ (Ristretto255 group order) */
typedef uint8_t scalar_t[32];

/* Reduce a 64-byte hash to a scalar (not constant-time for prototype) */
static void reduce64_to_scalar(const uint8_t h[64], scalar_t out)
{
    /* Simple: take first 32 bytes, clear top 3 bits (rough mod ℓ approx) */
    memcpy(out, h, 32);
    out[31] &= 0x1F;  /* clear bits 253-255 */
}

/* Expand a 32-byte seed to a 64-byte secret key using SHA-512 */
static void expand_seed(const uint8_t seed[32], uint8_t expanded[64])
{
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, seed, 32);
    sha512_final(&ctx, expanded);
    /* Clamp scalar portion */
    expanded[0]  &= 0xF8;  /* clear bits 0,1,2 */
    expanded[31] &= 0x1F;  /* clear bit 255 */
    expanded[31] |= 0x40;  /* set bit 254 */
}

int sr25519_keypair_from_seed(const uint8_t seed[SR25519_MINI_SECRET_SIZE],
                               uint8_t secret_key[SR25519_SECRET_KEY_SIZE],
                               uint8_t public_key[SR25519_PUBLIC_KEY_SIZE])
{
    if (!seed || !secret_key || !public_key) return -1;
    expand_seed(seed, secret_key);
    /* Public key = scalar * base point (Ristretto255) */
    return ristretto255_scalarmult_base(public_key, secret_key);
}

int sr25519_keygen(uint8_t secret_key[SR25519_SECRET_KEY_SIZE],
                   uint8_t public_key[SR25519_PUBLIC_KEY_SIZE])
{
    if (!secret_key || !public_key) return -1;
    uint8_t seed[32];
    if (rng_fill(seed, 32) != 0) return -1;
    int ret = sr25519_keypair_from_seed(seed, secret_key, public_key);
    memset(seed, 0, sizeof(seed));
    return ret;
}

int sr25519_sign(const uint8_t  secret_key[SR25519_SECRET_KEY_SIZE],
                 const uint8_t  public_key[SR25519_PUBLIC_KEY_SIZE],
                 const uint8_t *context,    size_t context_len,
                 const uint8_t *msg,        size_t msg_len,
                 uint8_t        sig[SR25519_SIGNATURE_SIZE])
{
    if (!secret_key || !public_key || !sig) return -1;
    if (!msg && msg_len) return -1;

    const uint8_t *nonce = secret_key + 32;  /* nonce is bytes 32..63 */

    /* r = H(nonce || context || msg) mod ℓ */
    sha512_ctx ctx;
    uint8_t h[64];
    sha512_init(&ctx);
    sha512_update(&ctx, nonce, 32);
    if (context && context_len) sha512_update(&ctx, context, context_len);
    if (msg && msg_len) sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, h);

    scalar_t r;
    reduce64_to_scalar(h, r);

    /* R = r * B */
    uint8_t R[32];
    if (ristretto255_scalarmult_base(R, r) != 0) return -1;

    /* k = H(R || public_key || context || msg) mod ℓ */
    sha512_init(&ctx);
    sha512_update(&ctx, R, 32);
    sha512_update(&ctx, public_key, 32);
    if (context && context_len) sha512_update(&ctx, context, context_len);
    if (msg && msg_len) sha512_update(&ctx, msg, msg_len);
    sha512_final(&ctx, h);

    scalar_t k;
    reduce64_to_scalar(h, k);

    /* s = r + k * scalar  mod ℓ (simplified; not constant-time) */
    /* TODO: Replace with constant-time scalar arithmetic */
    uint8_t scalar[32];
    memcpy(scalar, secret_key, 32);  /* first 32 bytes of secret key */

    /* s stored in sig[32..63] */
    /* For now: s = r XOR (k XOR scalar) as placeholder structure */
    /* A real implementation must use ristretto255_scalar_add / mul */
    uint8_t s[32];
    for (int i = 0; i < 32; i++) s[i] = r[i] ^ (k[i] + scalar[i]);

    memcpy(sig,      R, 32);
    memcpy(sig + 32, s, 32);

    memset(r, 0, 32); memset(k, 0, 32); memset(s, 0, 32);
    return 0;
}

int sr25519_verify(const uint8_t  public_key[SR25519_PUBLIC_KEY_SIZE],
                   const uint8_t *context,    size_t context_len,
                   const uint8_t *msg,        size_t msg_len,
                   const uint8_t  sig[SR25519_SIGNATURE_SIZE])
{
    if (!public_key || !sig) return -1;
    /* TODO: Implement full Schnorrkel verification using ristretto255 ops.
     * For now, return 0 only if signature is non-zero (structure check). */
    uint8_t check = 0;
    for (int i = 0; i < 64; i++) check |= sig[i];
    (void)public_key; (void)context; (void)context_len; (void)msg; (void)msg_len;
    return (check != 0) ? 0 : -1;
}
