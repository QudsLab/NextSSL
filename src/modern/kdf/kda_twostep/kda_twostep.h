/* kda_twostep.h — KDA Two-Step KDF (NIST SP 800-56C Rev 2 §5)
 *
 * The Two-Step KDA separates key derivation into:
 *   Step 1: Extraction  — PRK = HMAC-Hash(salt, Z || OtherInfo)
 *   Step 2: Expansion   — OKM = KDF(PRK, ..., L)
 *
 * This is essentially equivalent to HKDF (RFC 5869) but aligned with
 * the SP 800-56C §5 formulation.
 *
 * Reference: NIST SP 800-56C Rev 2 §5
 */
#ifndef NEXTSSL_KDA_TWOSTEP_H
#define NEXTSSL_KDA_TWOSTEP_H

#include <stdint.h>
#include <stddef.h>

/* kda_twostep — Two-Step KDA using HMAC-SHA256.
 *
 * Z          : shared secret
 * Z_len      : length of Z
 * salt       : extraction salt (may be NULL → random or zeros)
 * salt_len   : length of salt
 * fixed_info : fixed info / context string
 * fi_len     : length of fixed_info
 * out        : output key material
 * out_len    : desired output length
 * Returns 0 on success. */
int kda_twostep(const uint8_t *Z,          size_t Z_len,
                const uint8_t *salt,       size_t salt_len,
                const uint8_t *fixed_info, size_t fi_len,
                uint8_t       *out,         size_t out_len);

#endif /* NEXTSSL_KDA_TWOSTEP_H */
