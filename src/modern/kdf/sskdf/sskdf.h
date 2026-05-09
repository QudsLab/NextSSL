/* sskdf.h — Single-Step KDF (NIST SP 800-56C Rev 2 §4)
 *
 * SSKDF is another name for the One-Step KDA (see kda_onestep/).
 * This header provides SSKDF naming aliases for interoperability with
 * libraries/specs that use the "SSKDF" name (e.g. BouncyCastle, PKCS#11).
 *
 * Reference: NIST SP 800-56C Rev 2 §4.1, ISO/IEC 18033-2
 */
#ifndef NEXTSSL_SSKDF_H
#define NEXTSSL_SSKDF_H

#include "../kda_onestep/kda_onestep.h"

/* sskdf — Single-Step KDF using SHA-256 (alias for kda_onestep_hash). */
static inline int sskdf(const uint8_t *Z,          size_t Z_len,
                         const uint8_t *fixed_info, size_t fi_len,
                         uint8_t       *out,         size_t out_len)
{
    return kda_onestep_hash(Z, Z_len, fixed_info, fi_len, out, out_len);
}

/* sskdf_hmac — SSKDF using HMAC-SHA256 (alias for kda_onestep_hmac). */
static inline int sskdf_hmac(const uint8_t *Z,          size_t Z_len,
                               const uint8_t *salt,       size_t salt_len,
                               const uint8_t *fixed_info, size_t fi_len,
                               uint8_t       *out,         size_t out_len)
{
    return kda_onestep_hmac(Z, Z_len, salt, salt_len, fixed_info, fi_len, out, out_len);
}

#endif /* NEXTSSL_SSKDF_H */
