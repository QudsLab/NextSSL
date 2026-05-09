/* hkdf_expand_label.c — HKDF-Expand-Label (RFC 8446 §7.1) */
#include "hkdf_expand_label.h"
#include "../hkdf/hkdf.h"
#include "../../../hash/interface/hash_registry.h"
#include <string.h>

/* sha384_ops is declared in hash_registry.h */
extern const hash_ops_t sha384_ops;

/* Build the HkdfLabel encoding and call HKDF-Expand */
static int expand_label_inner(const uint8_t *secret, size_t secret_len,
                                const char *label, size_t label_len,
                                const uint8_t *context, size_t context_len,
                                uint8_t *out, size_t out_len,
                                const void *hash_ops)
{
    if (!secret || !label || out_len > 255) return -1;

    /* HkdfLabel encoding:
     *   length  (2 bytes big-endian)
     *   label_length (1 byte) + "tls13 " (6 bytes) + label
     *   context_length (1 byte) + context
     */
    static const char prefix[] = "tls13 ";
    size_t full_label_len = 6 + label_len;
    if (full_label_len > 249) return -1;  /* label field max 255, prefix=6 → max 249 */

    uint8_t hkdf_label[2 + 1 + 255 + 1 + 255];
    size_t pos = 0;

    hkdf_label[pos++] = (uint8_t)(out_len >> 8);
    hkdf_label[pos++] = (uint8_t)(out_len);
    hkdf_label[pos++] = (uint8_t)(full_label_len);
    memcpy(hkdf_label + pos, prefix, 6); pos += 6;
    memcpy(hkdf_label + pos, label, label_len); pos += label_len;
    hkdf_label[pos++] = (uint8_t)(context_len);
    if (context && context_len) {
        memcpy(hkdf_label + pos, context, context_len);
        pos += context_len;
    }

    return hkdf_expand_ex((const hash_ops_t *)hash_ops,
                           secret, secret_len,
                           hkdf_label, pos,
                           out, out_len);
}

int hkdf_expand_label(const uint8_t *secret,  size_t secret_len,
                       const char    *label,   size_t label_len,
                       const uint8_t *context, size_t context_len,
                       uint8_t       *out,     size_t out_len)
{
    /* NULL hash_ops → use SHA-256 default */
    return expand_label_inner(secret, secret_len, label, label_len,
                               context, context_len, out, out_len, NULL);
}

int hkdf_expand_label_sha384(const uint8_t *secret,  size_t secret_len,
                               const char    *label,   size_t label_len,
                               const uint8_t *context, size_t context_len,
                               uint8_t       *out,     size_t out_len)
{
    /* SHA-384 variant: use sha384_ops vtable (RFC 8446 §7.1 with SHA-384) */
    return expand_label_inner(secret, secret_len, label, label_len,
                               context, context_len, out, out_len, &sha384_ops);
}
