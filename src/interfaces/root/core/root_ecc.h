/**
 * @file root/core/root_ecc.h
 * @brief NextSSL Root — Explicit elliptic-curve algorithm interface.
 *
 * Naming: nextssl_root_ecc_<curve>_<operation>(...)
 *
 * Curves:
 *   ed25519   — Edwards25519 signatures + X25519 DH
 *   curve448  — X448 Diffie-Hellman (Curve448/Goldilocks)
 *   r255      — Ristretto255 group operations
 *   elligator — Elligator2 map/inverse (key obfuscation)
 */

#ifndef NEXTSSL_ROOT_ECC_H
#define NEXTSSL_ROOT_ECC_H

#include <stddef.h>
#include <stdint.h>
#include "../../../config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------
 * Ed25519 — Signatures
 * pk=32B  sk=64B (seed[32] || pk[32])  sig=64B
 * ------------------------------------------------------------------ */

/** Generate Ed25519 keypair from an internal CSPRNG seed. */
NEXTSSL_API int nextssl_root_ecc_ed25519_keygen(uint8_t pk[32], uint8_t sk[64]);

/** Sign: sig[64]. sk must be the 64-byte value from keygen. */
NEXTSSL_API int nextssl_root_ecc_ed25519_sign(uint8_t sig[64],
                                               const uint8_t *msg, size_t msg_len,
                                               const uint8_t sk[64]);

/** Verify: returns 1 valid, 0 invalid. */
NEXTSSL_API int nextssl_root_ecc_ed25519_verify(const uint8_t sig[64],
                                                 const uint8_t *msg, size_t msg_len,
                                                 const uint8_t pk[32]);

/* ------------------------------------------------------------------
 * X25519 — Diffie-Hellman
 * pk=32B  sk=32B  shared_secret=32B
 * ------------------------------------------------------------------ */

/** Generate X25519 keypair. */
NEXTSSL_API int nextssl_root_ecc_x25519_keygen(uint8_t pk[32], uint8_t sk[32]);

/** Compute shared secret: my_sk × their_pk → ss[32]. */
NEXTSSL_API int nextssl_root_ecc_x25519_exchange(const uint8_t my_sk[32],
                                                  const uint8_t their_pk[32],
                                                  uint8_t ss[32]);

/* ------------------------------------------------------------------
 * X448 — Diffie-Hellman over Curve448
 * pk=56B  sk=56B  shared_secret=56B
 * ------------------------------------------------------------------ */

#ifndef NEXTSSL_BUILD_LITE

/** Generate X448 keypair. */
NEXTSSL_API int nextssl_root_ecc_x448_keygen(uint8_t pk[56], uint8_t sk[56]);

/** Compute X448 shared secret. */
NEXTSSL_API int nextssl_root_ecc_x448_exchange(const uint8_t my_sk[56],
                                                const uint8_t their_pk[56],
                                                uint8_t ss[56]);

/* ------------------------------------------------------------------
 * Ristretto255 — prime-order group operations
 * Point size = 32B  Scalar size = 32B  Hash input = 64B
 * ------------------------------------------------------------------ */

/** Returns 1 if p is a valid Ristretto255 point, 0 if not. */
NEXTSSL_API int nextssl_root_ecc_r255_is_valid(const uint8_t p[32]);

/** Point addition: r = p + q. Returns 0 ok, -1 invalid input. */
NEXTSSL_API int nextssl_root_ecc_r255_add(uint8_t r[32],
                                           const uint8_t p[32],
                                           const uint8_t q[32]);

/** Point subtraction: r = p - q. Returns 0 ok, -1 invalid input. */
NEXTSSL_API int nextssl_root_ecc_r255_sub(uint8_t r[32],
                                           const uint8_t p[32],
                                           const uint8_t q[32]);

/** Map a 64-byte uniform hash to a Ristretto255 point (hash-to-group). */
NEXTSSL_API int nextssl_root_ecc_r255_from_hash(uint8_t p[32],
                                                 const uint8_t hash[64]);

/* ------------------------------------------------------------------
 * Elligator2 — steganographic key encoding
 * Maps a Curve25519 public key ↔ an indistinguishable 32-byte string.
 * ------------------------------------------------------------------ */

/**
 * Forward map: hidden[32] uniform random → curve point curve[32].
 * Used by the receiver to decode a disguised public key.
 */
NEXTSSL_API int nextssl_root_ecc_elligator2_map(uint8_t curve[32],
                                                 const uint8_t hidden[32]);

/**
 * Reverse map: curve point public_key[32] → hidden representative hidden[32].
 * tweak is a 1-byte value (0 or 1) influencing the representative.
 * Returns 0 on success (key has a valid representative), -1 if none.
 */
NEXTSSL_API int nextssl_root_ecc_elligator2_rev(uint8_t hidden[32],
                                                 const uint8_t public_key[32],
                                                 uint8_t tweak);

/**
 * Generate an Elligator2-compatible keypair from seed[32].
 * Outputs hidden[32] (the obfuscated key) and secret_key[32].
 */
NEXTSSL_API int nextssl_root_ecc_elligator2_keygen(uint8_t hidden[32],
                                                    uint8_t secret_key[32],
                                                    uint8_t seed[32]);

#endif /* NEXTSSL_BUILD_LITE */

#ifdef __cplusplus
}
#endif

#endif /* NEXTSSL_ROOT_ECC_H */
