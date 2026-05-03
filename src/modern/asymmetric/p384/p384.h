/* p384.h — P-384 (NIST secp384r1) ECDH/ECDSA stub (Plan 201 / Plan 203)
 *
 * Status: stub — returns -1 (not implemented).
 */
#ifndef MODERN_P384_H
#define MODERN_P384_H

#include <stddef.h>
#include <stdint.h>

#define P384_PRIVATE_KEY_SIZE   48
#define P384_PUBLIC_KEY_SIZE    96  /* uncompressed: x(48) ‖ y(48) */
#define P384_SHARED_SECRET_SIZE 48

int p384_keygen(uint8_t private_key[P384_PRIVATE_KEY_SIZE],
                uint8_t public_key[P384_PUBLIC_KEY_SIZE]);

int p384_ecdh(const uint8_t their_public[P384_PUBLIC_KEY_SIZE],
              const uint8_t our_private[P384_PRIVATE_KEY_SIZE],
              uint8_t       shared_secret[P384_SHARED_SECRET_SIZE]);

int p384_ecdsa_sign(const uint8_t private_key[P384_PRIVATE_KEY_SIZE],
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *sig_r, uint8_t *sig_s);

int p384_ecdsa_verify(const uint8_t public_key[P384_PUBLIC_KEY_SIZE],
                      const uint8_t *msg_hash, size_t hash_len,
                      const uint8_t *sig_r, const uint8_t *sig_s);

#endif /* MODERN_P384_H */
