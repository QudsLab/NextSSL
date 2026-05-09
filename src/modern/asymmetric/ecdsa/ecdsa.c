/* ecdsa.c — ECDSA over P-256/P-384/P-521
 *
 * Delegates to existing p256/p384/p521 backends.
 * For P-256 uses micro-ecc (uECC_secp256r1).
 * For P-384/P-521 uses the _nist_ecc backend.
 */
#include "ecdsa.h"
#include "../p256/p256.h"
#include "../p384/p384.h"
#include "../p521/p521.h"
#include <string.h>

static size_t order_bytes(ecdsa_curve_t curve)
{
    switch (curve) {
        case ECDSA_P256: return 32;
        case ECDSA_P384: return 48;
        case ECDSA_P521: return 66;
    }
    return 0;
}

int ecdsa_sign(ecdsa_curve_t  curve,
               const uint8_t *private_key, size_t priv_len,
               const uint8_t *hash,        size_t hash_len,
               uint8_t       *sig_r,
               uint8_t       *sig_s)
{
    if (!private_key || !hash || !sig_r || !sig_s) return -1;
    if (priv_len != order_bytes(curve)) return -1;

    switch (curve) {
        case ECDSA_P256:
            return p256_ecdsa_sign(private_key, hash, hash_len, sig_r, sig_s);
        case ECDSA_P384:
            return p384_ecdsa_sign(private_key, hash, hash_len, sig_r, sig_s);
        case ECDSA_P521:
            return p521_ecdsa_sign(private_key, hash, hash_len, sig_r, sig_s);
    }
    return -1;
}

int ecdsa_verify(ecdsa_curve_t  curve,
                 const uint8_t *public_key, size_t pub_len,
                 const uint8_t *hash,       size_t hash_len,
                 const uint8_t *sig_r,      size_t r_len,
                 const uint8_t *sig_s,      size_t s_len)
{
    if (!public_key || !hash || !sig_r || !sig_s) return -1;
    size_t order = order_bytes(curve);
    if (r_len != order || s_len != order) return -1;
    (void)pub_len;

    switch (curve) {
        case ECDSA_P256:
            return p256_ecdsa_verify(public_key, hash, hash_len, sig_r, sig_s);
        case ECDSA_P384:
            return p384_ecdsa_verify(public_key, hash, hash_len, sig_r, sig_s);
        case ECDSA_P521:
            return p521_ecdsa_verify(public_key, hash, hash_len, sig_r, sig_s);
    }
    return -1;
}

int ecdsa_keygen(ecdsa_curve_t curve,
                 uint8_t *private_key,
                 uint8_t *public_key)
{
    if (!private_key || !public_key) return -1;
    switch (curve) {
        case ECDSA_P256:
            return p256_keygen(private_key, public_key);
        case ECDSA_P384:
            return p384_keygen(private_key, public_key);
        case ECDSA_P521:
            return p521_keygen(private_key, public_key);
    }
    return -1;
}
