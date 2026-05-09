/* x448.h — X448 Diffie-Hellman function (RFC 7748 §5)
 *
 * X448 is the Diffie-Hellman function on Curve448-Goldilocks.
 * A 56-byte scalar and a 56-byte u-coordinate point are the inputs;
 * the output is a 56-byte shared u-coordinate.
 *
 * Key generation: pick a uniformly random 56-byte scalar, clamp it, then
 * compute the public key as x448_scalarmult_base(scalar).
 *
 * Key exchange: shared_secret = x448_scalarmult(their_public, our_scalar)
 *
 * Delegates to _curve448_backend for all arithmetic.
 */
#ifndef NEXTSSL_X448_H
#define NEXTSSL_X448_H

#include <stdint.h>
#include <stddef.h>

#define X448_KEY_SIZE    56u  /* scalar and point size in bytes */

/* Clamp a raw 56-byte scalar per RFC 7748 §5 (curve448).
 * Must be called on every freshly generated or imported private key. */
void x448_clamp(uint8_t scalar[X448_KEY_SIZE]);

/* x448_scalarmult_base — multiply the canonical base point by scalar.
 * Writes the 56-byte public key into public_key.
 * Returns 0 on success, -1 on error. */
int x448_scalarmult_base(uint8_t       public_key[X448_KEY_SIZE],
                         const uint8_t scalar[X448_KEY_SIZE]);

/* x448_scalarmult — multiply public_key by scalar (Diffie-Hellman step).
 * Writes the 56-byte shared secret into out.
 * Returns 0 on success, -1 if the result is the all-zero point (invalid). */
int x448_scalarmult(uint8_t       out[X448_KEY_SIZE],
                    const uint8_t scalar[X448_KEY_SIZE],
                    const uint8_t public_key[X448_KEY_SIZE]);

/* x448_keygen — generate a fresh key pair from OS entropy.
 * private_key and public_key must each be X448_KEY_SIZE bytes.
 * Returns 0 on success, -1 on entropy failure. */
int x448_keygen(uint8_t private_key[X448_KEY_SIZE],
                uint8_t public_key[X448_KEY_SIZE]);

#endif /* NEXTSSL_X448_H */
