/* kda_onestep.h — KDA One-Step KDF (NIST SP 800-56C Rev 2 §4)
 *
 * SP 800-56C One-Step KDA is identical to ConcatKDF when using a hash
 * function as the auxiliary function H.  When H = HMAC-hash, a salt is added.
 *
 * H(x) = Hash(x) option:
 *   OKM = Hash(0x00000001 || Z || FixedInfo) [|| Hash(0x00000002 || Z || FixedInfo) || ...]
 *
 * H(x) = HMAC-Hash(salt, x) option:
 *   OKM = HMAC-Hash(salt, 0x00000001 || Z || FixedInfo) [|| ...]
 *
 * Reference: NIST SP 800-56C Rev 2 §4.1
 */
#ifndef NEXTSSL_KDA_ONESTEP_H
#define NEXTSSL_KDA_ONESTEP_H

#include <stdint.h>
#include <stddef.h>

/* kda_onestep_hash — One-Step KDA using H = SHA-256.
 * Z, fixed_info, out: standard inputs/output.
 * Returns 0 on success. */
int kda_onestep_hash(const uint8_t *Z,          size_t Z_len,
                      const uint8_t *fixed_info, size_t fi_len,
                      uint8_t       *out,         size_t out_len);

/* kda_onestep_hmac — One-Step KDA using H = HMAC-SHA256 with salt.
 * salt may be NULL (defaults to block of zeros). */
int kda_onestep_hmac(const uint8_t *Z,          size_t Z_len,
                      const uint8_t *salt,       size_t salt_len,
                      const uint8_t *fixed_info, size_t fi_len,
                      uint8_t       *out,         size_t out_len);

#endif /* NEXTSSL_KDA_ONESTEP_H */
