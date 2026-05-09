/* concat_kdf.h — ConcatKDF / Single-Step KDF (NIST SP 800-56C Rev 2 §4)
 *
 * Also known as KDA One-Step KDF when H = HMAC, or as ConcatKDF in JWA.
 *
 * Z_len || AlgorithmID || PartyUInfo || PartyVInfo [|| SuppPubInfo] [|| SuppPrivInfo]
 * Key Material = H(Counter || Z || OtherInfo) [concatenated as needed]
 *
 * Reference: NIST SP 800-56C Rev 2 §4.1, RFC 7518 §4.6.2
 */
#ifndef NEXTSSL_CONCAT_KDF_H
#define NEXTSSL_CONCAT_KDF_H

#include <stdint.h>
#include <stddef.h>

/* concat_kdf — ConcatKDF using SHA-256.
 *
 * Z          : shared secret input
 * Z_len      : length of Z
 * other_info : OtherInfo concatenation (AlgorithmID || PartyUInfo || PartyVInfo || ...)
 * oi_len     : length of other_info
 * out        : output key material
 * out_len    : desired output length
 * Returns 0 on success, -1 on error. */
int concat_kdf(const uint8_t *Z,          size_t Z_len,
               const uint8_t *other_info, size_t oi_len,
               uint8_t       *out,         size_t out_len);

/* concat_kdf_sha384 — same using SHA-384. */
int concat_kdf_sha384(const uint8_t *Z,          size_t Z_len,
                       const uint8_t *other_info, size_t oi_len,
                       uint8_t       *out,         size_t out_len);

#endif /* NEXTSSL_CONCAT_KDF_H */
