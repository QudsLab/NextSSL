/* kdf_sp800_108.h — SP 800-108 KDF in Counter, Feedback, and Double-Pipeline modes
 *
 * Reference: NIST SP 800-108 Rev 1
 * All three iteration modes are provided using HMAC-SHA256 as the PRF.
 */
#ifndef NEXTSSL_KDF_SP800_108_H
#define NEXTSSL_KDF_SP800_108_H

#include <stdint.h>
#include <stddef.h>

/* kdf_sp800_108_counter — Counter Mode KDF (§4.1)
 *
 * KI        : key derivation key (PRF key)
 * KI_len    : length of KI
 * label     : purpose label
 * label_len : length of label
 * context   : context data
 * ctx_len   : length of context
 * out       : output buffer
 * out_len   : desired output length
 * Returns 0 on success. */
int kdf_sp800_108_counter(const uint8_t *KI,      size_t KI_len,
                           const uint8_t *label,   size_t label_len,
                           const uint8_t *context, size_t ctx_len,
                           uint8_t       *out,     size_t out_len);

/* kdf_sp800_108_feedback — Feedback Mode KDF (§4.2)
 * IV        : optional initialization vector (32 bytes or NULL) */
int kdf_sp800_108_feedback(const uint8_t *KI,      size_t KI_len,
                            const uint8_t *IV,      size_t IV_len,
                            const uint8_t *label,   size_t label_len,
                            const uint8_t *context, size_t ctx_len,
                            uint8_t       *out,     size_t out_len);

/* kdf_sp800_108_double_pipeline — Double-Pipeline Mode KDF (§4.3) */
int kdf_sp800_108_double_pipeline(const uint8_t *KI,      size_t KI_len,
                                   const uint8_t *label,   size_t label_len,
                                   const uint8_t *context, size_t ctx_len,
                                   uint8_t       *out,     size_t out_len);

#endif /* NEXTSSL_KDF_SP800_108_H */
