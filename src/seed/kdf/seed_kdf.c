#include "seed_kdf.h"
#include "../../PQCrypto/common/hkdf/hkdf.h"

/*
 * seed_kdf_derive — thin wrapper over hkdf() (HKDF-SHA256, RFC 5869).
 *
 * HKDF ceiling: okm_len ≤ 255 × HashLen = 255 × 32 = 8160 bytes.
 * hkdf() enforces this internally and returns non-zero on overflow.
 */
int seed_kdf_derive(const uint8_t *ikm,   size_t ikm_len,
                    const uint8_t *salt,  size_t salt_len,
                    const uint8_t *info,  size_t info_len,
                    uint8_t       *out,   size_t out_len) {
    if (!ikm || ikm_len == 0 || !out || out_len == 0) return -1;
    return hkdf(salt, salt_len, ikm, ikm_len, info, info_len, out, out_len);
}
