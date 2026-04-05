/* p521.h — P-521 (NIST secp521r1) ECDH/ECDSA stub (Plan 201 / Plan 203)
 *
 * Status: stub — returns -1 (not implemented).
 */
#ifndef MODERN_P521_H
#define MODERN_P521_H

#include <stddef.h>
#include <stdint.h>

#define P521_PRIVATE_KEY_SIZE   66
#define P521_PUBLIC_KEY_SIZE   132  /* uncompressed: x(66) ‖ y(66) */
#define P521_SHARED_SECRET_SIZE 66

int p521_keygen(uint8_t private_key[P521_PRIVATE_KEY_SIZE],
                uint8_t public_key[P521_PUBLIC_KEY_SIZE]);

int p521_ecdh(const uint8_t their_public[P521_PUBLIC_KEY_SIZE],
              const uint8_t our_private[P521_PRIVATE_KEY_SIZE],
              uint8_t       shared_secret[P521_SHARED_SECRET_SIZE]);

int p521_ecdsa_sign(const uint8_t private_key[P521_PRIVATE_KEY_SIZE],
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *sig_r, uint8_t *sig_s);

int p521_ecdsa_verify(const uint8_t public_key[P521_PUBLIC_KEY_SIZE],
                      const uint8_t *msg_hash, size_t hash_len,
                      const uint8_t *sig_r, const uint8_t *sig_s);

#endif /* MODERN_P521_H */
