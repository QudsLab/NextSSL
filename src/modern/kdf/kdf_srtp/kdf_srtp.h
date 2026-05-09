/* kdf_srtp.h — SRTP Key Derivation (RFC 3711 §4.3.1)
 *
 * SRTP derives cipher keys, salts, and HMAC keys from a master key
 * using AES counter mode as a PRF:
 *
 *   r = index DIV key_derivation_rate
 *   x = label XOR (r << 16)
 *   OKM = AES-CM(master_key, master_salt XOR (x << 16), 0)
 *
 * Labels: 0x00 = cipher key, 0x01 = salt key, 0x02 = HMAC key
 *
 * Reference: RFC 3711 §4.3.1
 */
#ifndef NEXTSSL_KDF_SRTP_H
#define NEXTSSL_KDF_SRTP_H

#include <stdint.h>
#include <stddef.h>

/* SRTP label values */
#define SRTP_LABEL_CIPHER    0x00u
#define SRTP_LABEL_SALT      0x01u
#define SRTP_LABEL_AUTH      0x02u

/* srtp_kdf — Derive SRTP key material for the given label.
 *
 * master_key   : AES-128 master key (16 bytes)
 * master_salt  : 14-byte salt
 * index        : SRTP packet index (for KDR; use 0 for initial derivation)
 * kdr          : key derivation rate (0 = derive once only)
 * label        : SRTP_LABEL_CIPHER, _SALT, or _AUTH
 * out          : output buffer
 * out_len      : desired length (16 for cipher key, 14 for salt, 20 for HMAC-SHA1 key)
 * Returns 0 on success. */
int srtp_kdf(const uint8_t  master_key[16],
              const uint8_t  master_salt[14],
              uint64_t       index,
              uint64_t       kdr,
              uint8_t        label,
              uint8_t       *out,
              size_t         out_len);

#endif /* NEXTSSL_KDF_SRTP_H */
