/* hkdf_expand_label.h — HKDF-Expand-Label (RFC 8446 §7.1 / TLS 1.3)
 *
 * HKDF-Expand-Label(Secret, Label, Context, Length) is a specialization
 * of HKDF-Expand used throughout TLS 1.3 key derivation.
 *
 * HkdfLabel = struct {
 *     uint16 length;
 *     opaque label<7..255>;    // "tls13 " + Label
 *     opaque context<0..255>;
 * };
 * output = HKDF-Expand(Secret, HkdfLabel, Length)
 *
 * Reference: RFC 8446 §7.1
 */
#ifndef NEXTSSL_HKDF_EXPAND_LABEL_H
#define NEXTSSL_HKDF_EXPAND_LABEL_H

#include <stdint.h>
#include <stddef.h>

/* hkdf_expand_label — compute HKDF-Expand-Label.
 *
 * secret      : HKDF PRK (from a prior Extract step)
 * secret_len  : length of secret
 * label       : label string (without "tls13 " prefix — that is prepended here)
 * label_len   : length of label
 * context     : transcript hash or empty byte string
 * context_len : length of context
 * out         : output buffer
 * out_len     : desired output length (≤ 255 bytes)
 * Returns 0 on success, -1 on error. */
int hkdf_expand_label(const uint8_t *secret,  size_t secret_len,
                       const char    *label,   size_t label_len,
                       const uint8_t *context, size_t context_len,
                       uint8_t       *out,     size_t out_len);

/* hkdf_expand_label_sha384 — same but using SHA-384 (TLS 1.3 cipher suites
 * that use SHA-384, e.g. TLS_AES_256_GCM_SHA384). */
int hkdf_expand_label_sha384(const uint8_t *secret,  size_t secret_len,
                               const char    *label,   size_t label_len,
                               const uint8_t *context, size_t context_len,
                               uint8_t       *out,     size_t out_len);

#endif /* NEXTSSL_HKDF_EXPAND_LABEL_H */
