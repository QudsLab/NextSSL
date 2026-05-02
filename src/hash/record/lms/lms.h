/* lms.h — LMS stateful hash-based signatures (SP 800-208 / RFC 8554 §5)
 *
 * WARNING — STATEFUL SCHEME:
 *   An LMS private key can sign at most 2^h messages.  After each signing
 *   operation the leaf index q MUST be incremented and the updated private
 *   key state MUST be persisted before returning the signature.
 *   Failing to persist state or cloning the private key will cause OTS key
 *   reuse, completely breaking security.
 */
#ifndef NEXTSSL_LMS_H
#define NEXTSSL_LMS_H

#include "lms_params.h"
#include "lmots.h"
#include <stdint.h>
#include <stddef.h>

/* Maximum LMS signature size (H=5, w=1): ~8700 bytes */
#define LMS_SIG_MAX_LEN  (4 + 4 + LMOTS_SIG_MAX_LEN + 5 * 32)

/* ── Private key (in-memory representation) ─────────────────────────────── */

typedef struct lms_private_key {
    lms_type_t          lms_type;
    lmots_type_t        lmots_type;
    uint8_t             I[16];    /* 16-byte tree identifier */
    uint32_t            q;        /* current leaf index (monotonically increasing) */
    uint8_t             seed[32]; /* SEED for OTS key generation */
    uint8_t            *T;        /* Merkle tree nodes: (2^(h+1) - 1) × m bytes */
} lms_private_key_t;

/* ── Key generation ──────────────────────────────────────────────────────── */

/* Generate a fresh LMS key pair.
 * I: 16-byte identifier (caller supplies; use a random or unique value)
 * seed: 32-byte seed for OTS key derivation
 * priv: caller-allocated, filled on success
 * pub:  caller-allocated, at least 4+4+16+m bytes
 * Returns 0 on success. */
int lms_keygen(lms_type_t lms_type, lmots_type_t lmots_type,
               const uint8_t I[16], const uint8_t seed[32],
               lms_private_key_t *priv,
               uint8_t *pub, size_t *pub_len);

/* Free tree storage inside priv (does not free priv itself) */
void lms_private_key_free(lms_private_key_t *priv);

/* ── Sign ────────────────────────────────────────────────────────────────── */

/* Sign a message using the current leaf q, then increment q.
 * sig: output buffer, at least LMS_SIG_MAX_LEN bytes.
 * sig_len: set to actual signature length.
 * Returns 0 on success, -1 if key is exhausted. */
int lms_sign(lms_private_key_t *priv,
             const uint8_t *msg, size_t msglen,
             uint8_t *sig, size_t *sig_len);

/* ── Verify ──────────────────────────────────────────────────────────────── */

/* Verify an LMS signature.
 * pub: serialised public key (as produced by lms_keygen).
 * Returns 0 on success (signature valid), -1 on failure. */
int lms_verify(const uint8_t *pub,  size_t pub_len,
               const uint8_t *msg,  size_t msglen,
               const uint8_t *sig,  size_t sig_len);

#endif /* NEXTSSL_LMS_H */
