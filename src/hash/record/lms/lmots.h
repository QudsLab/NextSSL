/* lmots.h — LM-OTS one-time signature (SP 800-208 / RFC 8554 §4)
 *
 * WARNING — ONE-TIME USE:
 *   Each LM-OTS private key MUST be used to sign at most ONE message.
 *   Re-signing with the same key completely breaks security.
 */
#ifndef NEXTSSL_LMOTS_H
#define NEXTSSL_LMOTS_H

#include "lms_params.h"
#include <stdint.h>
#include <stddef.h>

/* Maximum LM-OTS signature size (n=32, p=265): 4 + 32 + 265*32 = 8516 bytes */
#define LMOTS_SIG_MAX_LEN 8516

/* ── Key generation ──────────────────────────────────────────────────────── */

/* Generate an LM-OTS private key from a seed and leaf index.
 * seed: I (16-byte identifier) || q (4-byte leaf index)
 * private_key: output, p*n bytes.
 * Returns 0 on success. */
int lmots_keygen(const lmots_params_t *p,
                 const uint8_t I[16], uint32_t q,
                 const uint8_t *seed, size_t seed_len,
                 uint8_t *private_key);

/* Compute public key from private key.
 * public_key: output, n bytes (a single hash chain final value). */
int lmots_pubkey_from_privkey(const lmots_params_t *p,
                               const uint8_t I[16], uint32_t q,
                               const uint8_t *private_key,
                               uint8_t *public_key);

/* ── Sign ────────────────────────────────────────────────────────────────── */

/* Sign a message.
 * sig: output buffer, at least LMOTS_SIG_MAX_LEN bytes.
 * sig_len: set to actual signature length on success.
 * Returns 0 on success. */
int lmots_sign(const lmots_params_t *p,
               const uint8_t I[16], uint32_t q,
               const uint8_t *private_key,
               const uint8_t *msg, size_t msglen,
               uint8_t *sig, size_t *sig_len);

/* ── Verify ──────────────────────────────────────────────────────────────── */

/* Recover the candidate public key from a signature and message.
 * kc: output, n bytes.  Compare to stored public key to verify.
 * Returns 0 on success (signature parsed correctly), -1 on error. */
int lmots_verify(const lmots_params_t *p,
                 const uint8_t I[16], uint32_t q,
                 const uint8_t *sig, size_t sig_len,
                 const uint8_t *msg, size_t msglen,
                 uint8_t *kc);

#endif /* NEXTSSL_LMOTS_H */
