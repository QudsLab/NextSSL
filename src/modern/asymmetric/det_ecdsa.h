/* det_ecdsa.h — Deterministic ECDSA (RFC 6979 / FIPS 186-5 Det-ECDSA)
 *
 * RFC 6979 derives the per-signature nonce k deterministically from the
 * private key and the message hash using HMAC-DRBG, eliminating the need
 * for a per-signature random source.
 *
 * Supported curves: P-256, P-384, P-521.
 */
#ifndef NEXTSSL_DET_ECDSA_H
#define NEXTSSL_DET_ECDSA_H

#include <stdint.h>
#include <stddef.h>

typedef enum {
    DET_ECDSA_P256 = 0,
    DET_ECDSA_P384 = 1,
    DET_ECDSA_P521 = 2
} det_ecdsa_curve_t;

/* Sign msg_hash with a deterministic k derived via RFC 6979.
 * private_key : big-endian, curve order length (32 / 48 / 66 bytes)
 * msg_hash    : hash of the message (any length; will be truncated/padded to curve order)
 * sig_r, sig_s: output signature components (must be curve order length each)
 * Returns 0 on success, -1 on error. */
int det_ecdsa_sign(det_ecdsa_curve_t curve,
                   const uint8_t *private_key, size_t priv_len,
                   const uint8_t *msg_hash,    size_t hash_len,
                   uint8_t       *sig_r,
                   uint8_t       *sig_s);

/* Verify ECDSA signature (works for both random and deterministic signatures).
 * public_key: uncompressed point (0x04 || x || y) or just x||y depending on curve API.
 * Returns 0 on success (valid), -1 on failure. */
int det_ecdsa_verify(det_ecdsa_curve_t curve,
                     const uint8_t *public_key, size_t pub_len,
                     const uint8_t *msg_hash,   size_t hash_len,
                     const uint8_t *sig_r,      size_t r_len,
                     const uint8_t *sig_s,      size_t s_len);

#endif /* NEXTSSL_DET_ECDSA_H */
