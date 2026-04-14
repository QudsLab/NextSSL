/* p256.h — P-256 (NIST secp256r1) ECDH/ECDSA (Plan 201 / Plan 203)
 *
 * Status: implemented via micro-ecc (uECC_secp256r1).
 * RNG is wired to rng_fill() for key generation.
 */
#ifndef MODERN_P256_H
#define MODERN_P256_H

#include <stddef.h>
#include <stdint.h>

#define P256_PRIVATE_KEY_SIZE   32
#define P256_PUBLIC_KEY_SIZE    64  /* uncompressed: x(32) ‖ y(32) */
#define P256_SHARED_SECRET_SIZE 32

/* Key generation */
int p256_keygen(uint8_t private_key[P256_PRIVATE_KEY_SIZE],
                uint8_t public_key[P256_PUBLIC_KEY_SIZE]);

/* ECDH shared-secret derivation */
int p256_ecdh(const uint8_t their_public[P256_PUBLIC_KEY_SIZE],
              const uint8_t our_private[P256_PRIVATE_KEY_SIZE],
              uint8_t       shared_secret[P256_SHARED_SECRET_SIZE]);

/* ECDSA sign */
int p256_ecdsa_sign(const uint8_t private_key[P256_PRIVATE_KEY_SIZE],
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *sig_r, uint8_t *sig_s);

/* ECDSA verify */
int p256_ecdsa_verify(const uint8_t public_key[P256_PUBLIC_KEY_SIZE],
                      const uint8_t *msg_hash, size_t hash_len,
                      const uint8_t *sig_r, const uint8_t *sig_s);

#endif /* MODERN_P256_H */
