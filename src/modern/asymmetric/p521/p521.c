/* p521.c — P-521 (NIST secp521r1) — stub pending capable ECC library (Plan 205)
 *
 * micro-ecc (used for P-256) does NOT support P-384 or P-521.
 * Requires mbedTLS (Apache 2.0) or BearSSL (MIT) for secp521r1 support.
 * All functions return -1 until integrated.
 */
#include "p521.h"

int p521_keygen(uint8_t private_key[P521_PRIVATE_KEY_SIZE],
                uint8_t public_key[P521_PUBLIC_KEY_SIZE])
{ (void)private_key; (void)public_key; return -1; }

int p521_ecdh(const uint8_t their_public[P521_PUBLIC_KEY_SIZE],
              const uint8_t our_private[P521_PRIVATE_KEY_SIZE],
              uint8_t       shared_secret[P521_SHARED_SECRET_SIZE])
{ (void)their_public; (void)our_private; (void)shared_secret; return -1; }

int p521_ecdsa_sign(const uint8_t private_key[P521_PRIVATE_KEY_SIZE],
                    const uint8_t *msg_hash, size_t hash_len,
                    uint8_t *sig_r, uint8_t *sig_s)
{ (void)private_key; (void)msg_hash; (void)hash_len; (void)sig_r; (void)sig_s; return -1; }

int p521_ecdsa_verify(const uint8_t public_key[P521_PUBLIC_KEY_SIZE],
                      const uint8_t *msg_hash, size_t hash_len,
                      const uint8_t *sig_r, const uint8_t *sig_s)
{ (void)public_key; (void)msg_hash; (void)hash_len; (void)sig_r; (void)sig_s; return -1; }
