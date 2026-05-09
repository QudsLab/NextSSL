/* kdf_ansi_x963.h — ANSI X9.63 Key Derivation Function
 *
 * X9.63 KDF is used in ECIES and ECDH key agreement:
 *   K(i) = Hash(Z || Counter || SharedInfo)
 *   Counter starts at 0x00000001 and increments
 *
 * Reference: ANSI X9.63-2011 §5.4, SEC1 v2.0 §3.6.1
 */
#ifndef NEXTSSL_KDF_ANSI_X963_H
#define NEXTSSL_KDF_ANSI_X963_H

#include <stdint.h>
#include <stddef.h>

/* ansi_x963_kdf — derive key material using SHA-256.
 *
 * Z           : shared secret (ECDH output)
 * Z_len       : length of Z
 * shared_info : optional additional input (can be NULL)
 * si_len      : length of shared_info
 * out         : output key material
 * out_len     : desired output length
 * Returns 0 on success, -1 on error. */
int ansi_x963_kdf(const uint8_t *Z,           size_t Z_len,
                   const uint8_t *shared_info, size_t si_len,
                   uint8_t       *out,          size_t out_len);

/* ansi_x963_kdf_sha384 — same using SHA-384. */
int ansi_x963_kdf_sha384(const uint8_t *Z,           size_t Z_len,
                          const uint8_t *shared_info, size_t si_len,
                          uint8_t       *out,          size_t out_len);

#endif /* NEXTSSL_KDF_ANSI_X963_H */
