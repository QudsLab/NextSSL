/* dh.h — Finite-field Diffie-Hellman key exchange (RFC 3526 / FIPS 186)
 *
 * Supports RFC 3526 modular groups at 2048, 3072, and 4096 bits.
 * Keys are big-endian byte arrays of length modulus_bytes.
 *
 * NOTE: FFDH requires a large-integer arithmetic backend.
 * Wire to a bignum library (libtommath or WolfSSL fp_int) to activate.
 * Reference: examples/c/dh/
 */
#ifndef NEXTSSL_DH_H
#define NEXTSSL_DH_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    DH_GROUP_2048 = 14,  /* RFC 3526 group 14 */
    DH_GROUP_3072 = 15,  /* RFC 3526 group 15 */
    DH_GROUP_4096 = 16   /* RFC 3526 group 16 */
} dh_group_t;

/* Opaque DH context */
typedef struct dh_ctx dh_ctx_t;

/* Allocate a DH context for the given group.
 * Returns non-NULL on success, NULL on failure. */
dh_ctx_t *dh_ctx_new(dh_group_t group);
void       dh_ctx_free(dh_ctx_t *ctx);

/* Generate a DH key pair.
 * private_key: output; caller-allocated, dh_private_key_size() bytes
 * public_key : output; caller-allocated, dh_public_key_size() bytes
 * Returns 0 on success, -1 on error. */
int dh_keygen(dh_ctx_t *ctx,
              uint8_t *private_key,
              uint8_t *public_key);

/* Compute the shared secret from our private key and their public key.
 * shared: caller-allocated, dh_public_key_size() bytes
 * Returns 0 on success, -1 on error. */
int dh_shared_secret(dh_ctx_t       *ctx,
                     const uint8_t  *private_key,
                     const uint8_t  *their_public,
                     uint8_t        *shared,
                     size_t         *shared_len);

/* Key size helpers */
size_t dh_private_key_size(dh_group_t group);  /* private exponent size */
size_t dh_public_key_size (dh_group_t group);  /* modulus byte length   */

#endif /* NEXTSSL_DH_H */
