/* ecdsa.h — ECDSA signature over NIST curves (FIPS 186-4 / ANSI X9.62)
 *
 * Supports P-256, P-384, P-521.
 * Uses the _nist_ecc / p256/p384/p521 backends already present.
 *
 * Signature format: raw (r || s), each component big-endian, padded to
 * the curve order byte length (32/48/66 bytes).
 * Total signature: 64/96/132 bytes.
 */
#ifndef NEXTSSL_ECDSA_H
#define NEXTSSL_ECDSA_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    ECDSA_P256 = 0,  /* P-256  / secp256r1 */
    ECDSA_P384 = 1,  /* P-384  / secp384r1 */
    ECDSA_P521 = 2   /* P-521  / secp521r1 */
} ecdsa_curve_t;

/* Order byte sizes */
#define ECDSA_P256_ORDER_BYTES  32u
#define ECDSA_P384_ORDER_BYTES  48u
#define ECDSA_P521_ORDER_BYTES  66u

/* Maximum signature size (r || s for P-521) */
#define ECDSA_MAX_SIG_BYTES     132u
/* Maximum public key size (0x04 || x || y for P-521) */
#define ECDSA_MAX_PUB_BYTES     133u

/* ecdsa_sign — sign a message hash.
 * curve      : curve selector
 * private_key: big-endian private scalar (order_bytes)
 * hash       : pre-computed message digest
 * hash_len   : digest length in bytes
 * sig_r      : output r component (order_bytes)
 * sig_s      : output s component (order_bytes)
 * Returns 0 on success, -1 on error. */
int ecdsa_sign(ecdsa_curve_t  curve,
               const uint8_t *private_key, size_t priv_len,
               const uint8_t *hash,        size_t hash_len,
               uint8_t       *sig_r,
               uint8_t       *sig_s);

/* ecdsa_verify — verify a signature.
 * public_key: uncompressed point (0x04 || x || y) or x||y
 * Returns 0 on success (valid), -1 on failure. */
int ecdsa_verify(ecdsa_curve_t  curve,
                 const uint8_t *public_key, size_t pub_len,
                 const uint8_t *hash,       size_t hash_len,
                 const uint8_t *sig_r,      size_t r_len,
                 const uint8_t *sig_s,      size_t s_len);

/* ecdsa_keygen — generate a new key pair.
 * private_key: output private scalar (order_bytes)
 * public_key : output uncompressed point (1 + 2*order_bytes)
 * Returns 0 on success, -1 on error. */
int ecdsa_keygen(ecdsa_curve_t curve,
                 uint8_t *private_key,
                 uint8_t *public_key);

#endif /* NEXTSSL_ECDSA_H */
