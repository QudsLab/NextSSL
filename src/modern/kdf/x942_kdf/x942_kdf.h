/* x942_kdf.h — ANSI X9.42 Key Derivation Function (RFC 2631)
 *
 * X9.42 KDF is used in DH-based key agreement to derive symmetric keys:
 *   OtherInfo ::= SEQUENCE {
 *       keyInfo AlgorithmIdentifier,
 *       partyAInfo [0] OCTET STRING OPTIONAL,
 *       suppPubInfo [2] OCTET STRING
 *   }
 *   OKM = SHA-1(Z || 0x00000001 || OtherInfo) || SHA-1(Z || 0x00000002 || OtherInfo) || ...
 *
 * Note: X9.42 uses SHA-1; modern implementations may use SHA-256.
 * Both variants are provided.
 *
 * Reference: RFC 2631, ANSI X9.42-2003
 */
#ifndef NEXTSSL_X942_KDF_H
#define NEXTSSL_X942_KDF_H

#include <stdint.h>
#include <stddef.h>

/* x942_kdf — X9.42 KDF using SHA-256 (modern variant).
 *
 * Z          : DH shared secret
 * Z_len      : length of Z
 * other_info : OtherInfo DER encoding (caller constructs)
 * oi_len     : length of other_info
 * out        : output key material
 * out_len    : desired output length
 * Returns 0 on success. */
int x942_kdf(const uint8_t *Z,          size_t Z_len,
              const uint8_t *other_info, size_t oi_len,
              uint8_t       *out,         size_t out_len);

#endif /* NEXTSSL_X942_KDF_H */
