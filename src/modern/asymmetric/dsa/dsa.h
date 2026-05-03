/* dsa.h — Classical DSA (FIPS 186-4)
 *
 * Classical Discrete Logarithm-based DSA over prime-order subgroup.
 * DSA is legacy (superseded by ECDSA / ML-DSA) but required for FIPS 186-4
 * ACVP testing.
 *
 * Implementation note: this module provides the KAT-oriented API only
 * (deterministic sign given explicit k).  Key generation uses the DRBG.
 */
#ifndef NEXTSSL_MODERN_DSA_H
#define NEXTSSL_MODERN_DSA_H

#include <stdint.h>
#include <stddef.h>

/* Supported parameter set sizes (L, N) in bits */
typedef enum {
    DSA_PARAMS_1024_160 = 0,  /* FIPS 186-2 legacy */
    DSA_PARAMS_2048_224 = 1,
    DSA_PARAMS_2048_256 = 2,
    DSA_PARAMS_3072_256 = 3
} dsa_params_id_t;

/* Opaque DSA domain parameters (p, q, g).
 * Allocated via dsa_params_alloc, freed via dsa_params_free. */
typedef struct dsa_params dsa_params_t;

/* Opaque DSA key pair */
typedef struct dsa_key dsa_key_t;

/* ── Domain parameter generation ── */

/* Generate fresh DSA parameters for the given (L, N) size.
 * Returns non-NULL on success, NULL on failure.
 * Caller must call dsa_params_free(). */
dsa_params_t *dsa_params_generate(dsa_params_id_t id);

void dsa_params_free(dsa_params_t *params);

/* ── Key generation ── */

/* Generate a new DSA key pair.  Returns non-NULL on success. */
dsa_key_t *dsa_keygen(const dsa_params_t *params);

void dsa_key_free(dsa_key_t *key);

/* Export public key component y as a big-endian octet string.
 * buf must be at least params.L/8 bytes. */
int dsa_export_public(const dsa_key_t *key, uint8_t *buf, size_t buflen);

/* Export private key component x.  buf must be at least params.N/8 bytes. */
int dsa_export_private(const dsa_key_t *key, uint8_t *buf, size_t buflen);

/* Import keys from big-endian octet strings. */
dsa_key_t *dsa_import_keypair(const dsa_params_t *params,
                               const uint8_t *x, size_t xlen,
                               const uint8_t *y, size_t ylen);
dsa_key_t *dsa_import_public(const dsa_params_t *params,
                              const uint8_t *y, size_t ylen);

/* ── Sign / Verify ── */

/* Sign message hash with per-signature random k from DRBG.
 * hash_len should match the N parameter (20 / 28 / 32 bytes).
 * r_out and s_out must each be params.N/8 bytes. */
int dsa_sign(const dsa_key_t *key,
             const uint8_t *hash, size_t hash_len,
             uint8_t *r_out, uint8_t *s_out);

/* Deterministic sign — caller supplies k (big-endian, params.N/8 bytes).
 * Used for ACVP KAT testing where k is known. */
int dsa_sign_k(const dsa_key_t *key,
               const uint8_t *hash, size_t hash_len,
               const uint8_t *k,    size_t k_len,
               uint8_t *r_out, uint8_t *s_out);

/* Verify DSA signature.  Returns 0 on success (valid), -1 on failure. */
int dsa_verify(const dsa_key_t *key,
               const uint8_t *hash, size_t hash_len,
               const uint8_t *r,    size_t r_len,
               const uint8_t *s,    size_t s_len);

#endif /* NEXTSSL_MODERN_DSA_H */
