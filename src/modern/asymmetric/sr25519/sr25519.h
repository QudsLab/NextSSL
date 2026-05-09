/* sr25519.h — Sr25519 / Schnorrkel signature (Web3 Foundation spec)
 *
 * Sr25519 is Schnorr signatures over the Ristretto255 prime-order group.
 * It is designed for use in Substrate/Polkadot and Web3 ecosystems.
 *
 * Reference: https://github.com/w3f/schnorrkel
 * C reference: examples/c/sr25519/ (clone Zondax/c-schnorrkel)
 *
 * Key sizes:
 *   Mini secret key: 32 bytes (raw seed)
 *   Secret key:      64 bytes (expanded: 32-byte scalar || 32-byte nonce)
 *   Public key:      32 bytes (Ristretto255 compressed point)
 *   Signature:       64 bytes (R_compressed(32) || s(32))
 *
 * Depends on: curve_math/ristretto255.{h,c} (already present)
 */
#ifndef NEXTSSL_SR25519_H
#define NEXTSSL_SR25519_H

#include <stdint.h>
#include <stddef.h>

#define SR25519_MINI_SECRET_SIZE  32u  /* raw seed */
#define SR25519_SECRET_KEY_SIZE   64u  /* expanded (scalar || nonce) */
#define SR25519_PUBLIC_KEY_SIZE   32u  /* Ristretto255 compressed */
#define SR25519_SIGNATURE_SIZE    64u  /* (R, s) */
#define SR25519_KEYPAIR_SIZE      96u  /* secret(64) || public(32) */

/* Derive key pair from a 32-byte mini-secret key (seed).
 * secret_key: 64-byte expanded secret key output
 * public_key: 32-byte public key output
 * Returns 0 on success, -1 on error. */
int sr25519_keypair_from_seed(const uint8_t seed[SR25519_MINI_SECRET_SIZE],
                               uint8_t secret_key[SR25519_SECRET_KEY_SIZE],
                               uint8_t public_key[SR25519_PUBLIC_KEY_SIZE]);

/* Generate a random key pair using OS entropy.
 * Returns 0 on success, -1 on error. */
int sr25519_keygen(uint8_t secret_key[SR25519_SECRET_KEY_SIZE],
                   uint8_t public_key[SR25519_PUBLIC_KEY_SIZE]);

/* Sign a message.
 * context: application context string (may be NULL / empty)
 * sig    : 64-byte output signature
 * Returns 0 on success, -1 on error. */
int sr25519_sign(const uint8_t  secret_key[SR25519_SECRET_KEY_SIZE],
                 const uint8_t  public_key[SR25519_PUBLIC_KEY_SIZE],
                 const uint8_t *context,    size_t context_len,
                 const uint8_t *msg,        size_t msg_len,
                 uint8_t        sig[SR25519_SIGNATURE_SIZE]);

/* Verify a signature.
 * Returns 0 if valid, -1 if invalid. */
int sr25519_verify(const uint8_t  public_key[SR25519_PUBLIC_KEY_SIZE],
                   const uint8_t *context,    size_t context_len,
                   const uint8_t *msg,        size_t msg_len,
                   const uint8_t  sig[SR25519_SIGNATURE_SIZE]);

#endif /* NEXTSSL_SR25519_H */
