/* ecdh.h — Elliptic-Curve Diffie-Hellman (RFC 6090 / SP 800-56A)
 *
 * Supports P-256, P-384, P-521 via the existing pXXX backends,
 * plus X25519 (existing) and X448 (new).
 */
#ifndef NEXTSSL_ECDH_H
#define NEXTSSL_ECDH_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    ECDH_P256   = 0,
    ECDH_P384   = 1,
    ECDH_P521   = 2,
    ECDH_X25519 = 3,
    ECDH_X448   = 4
} ecdh_curve_t;

/* ecdh_shared_secret — compute the ECDH shared secret.
 * our_private : private key (curve-dependent size)
 * their_public: peer's public key (curve-dependent size)
 * shared      : output shared secret (caller-allocated)
 * shared_len  : in: buffer capacity; out: bytes written
 * Returns 0 on success, -1 on error. */
int ecdh_shared_secret(ecdh_curve_t   curve,
                       const uint8_t *our_private,  size_t priv_len,
                       const uint8_t *their_public, size_t pub_len,
                       uint8_t       *shared,       size_t *shared_len);

/* ecdh_keygen — generate a key pair for the given curve.
 * private_key / public_key: caller-allocated, use ecdh_key_size() to size.
 * Returns 0 on success. */
int ecdh_keygen(ecdh_curve_t curve,
                uint8_t *private_key,
                uint8_t *public_key);

/* Size helpers */
size_t ecdh_private_key_size(ecdh_curve_t curve);
size_t ecdh_public_key_size (ecdh_curve_t curve);
size_t ecdh_shared_size     (ecdh_curve_t curve);

#endif /* NEXTSSL_ECDH_H */
