/* pem.c — PEM encode / decode
 *
 * Uses radix_base64_encode / radix_base64_decode from
 * src/common/encoding/base64.h for the inner base64 layer.
 */
#include "pem.h"
#include "../../common/encoding/base64.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

/* ---- helpers ------------------------------------------------------------- */

static int type_valid(const char *t, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)t[i];
        if (!isalpha(c) && !isdigit(c) && c != ' ' && c != '-')
            return 0;
    }
    return 1;
}

/* Append |src|len bytes to |dst| starting at *|pos|, advancing *pos. */
static void append(char *dst, size_t dstcap, size_t *pos,
                   const char *src, size_t len)
{
    if (*pos + len > dstcap) return; /* caller checked size */
    memcpy(dst + *pos, src, len);
    *pos += len;
}

/* ---- public API ---------------------------------------------------------- */

int pem_encode(const char *type,
               const uint8_t *der, size_t der_len,
               char *dst, size_t dstcap,
               size_t *out_len)
{
    if (!type || !der || !dst) return PEM_ERR_INPUT;

    size_t type_len = strlen(type);
    if (type_len == 0 || type_len > PEM_MAX_TYPE_LEN) return PEM_ERR_TYPE;
    if (!type_valid(type, type_len)) return PEM_ERR_TYPE;

    /* Compute required size */
    size_t required = PEM_ENCODE_SIZE(der_len, type_len);
    if (dstcap < required) return PEM_ERR_BUFFER;

    /* Base64-encode the DER blob into a scratch buffer on the heap-ish ...
     * but we avoid malloc; PEM buffers are caller-supplied.  Use a
     * single-pass approach: write directly to dst. */

    size_t pos = 0;

    /* Header: -----BEGIN <TYPE>-----\n */
    append(dst, dstcap, &pos, "-----BEGIN ", 11);
    append(dst, dstcap, &pos, type, type_len);
    append(dst, dstcap, &pos, "-----\n", 6);

    /* Base64 content in 64-char lines (48 input bytes → 64 base64 chars) */
    for (size_t off = 0; off < der_len; off += 48) {
        size_t chunk = der_len - off;
        if (chunk > 48) chunk = 48;

        /* b64 for 48 bytes = 64 chars + padding */
        char b64buf[68];
        int rc = radix_base64_encode(der + off, chunk, b64buf, sizeof(b64buf));
        if (rc != 0) return PEM_ERR_BASE64;

        size_t blen = strlen(b64buf);
        append(dst, dstcap, &pos, b64buf, blen);
        append(dst, dstcap, &pos, "\n", 1);
    }

    /* Footer: -----END <TYPE>-----\n */
    append(dst, dstcap, &pos, "-----END ", 9);
    append(dst, dstcap, &pos, type, type_len);
    append(dst, dstcap, &pos, "-----\n", 6);

    dst[pos] = '\0';
    if (out_len) *out_len = pos;
    return PEM_OK;
}

int pem_decode(const char *pem, size_t pem_len,
               char *type_out, size_t type_cap,
               uint8_t *der_out, size_t der_cap, size_t *der_len)
{
    if (!pem || !type_out || !der_out || !der_len) return PEM_ERR_INPUT;

    /* Locate "-----BEGIN " */
    const char *begin_tag = "-----BEGIN ";
    const char *p = pem;
    const char *end = pem + pem_len;
    const char *header = NULL;

    while (p < end) {
        if ((size_t)(end - p) >= 11 && memcmp(p, begin_tag, 11) == 0) {
            header = p + 11;
            break;
        }
        p++;
    }
    if (!header) return PEM_ERR_FORMAT;

    /* Find the closing "-----" of the BEGIN line */
    const char *hend = header;
    while (hend < end && *hend != '-' && *hend != '\n') hend++;
    if (hend >= end || *hend != '-') return PEM_ERR_FORMAT;
    if ((size_t)(end - hend) < 5 || memcmp(hend, "-----", 5) != 0)
        return PEM_ERR_FORMAT;

    size_t tlen = (size_t)(hend - header);
    if (tlen == 0 || tlen > PEM_MAX_TYPE_LEN) return PEM_ERR_FORMAT;
    if (tlen + 1 > type_cap) return PEM_ERR_BUFFER;
    memcpy(type_out, header, tlen);
    type_out[tlen] = '\0';

    /* Skip past the begin line newline */
    const char *body = hend + 5;
    while (body < end && (*body == '\r' || *body == '\n')) body++;

    /* Build the "-----END <TYPE>-----" end tag */
    char end_tag[PEM_MAX_TYPE_LEN + 12];
    int end_tag_len = snprintf(end_tag, sizeof(end_tag), "-----END %.*s-----",
                               (int)tlen, type_out);
    if (end_tag_len < 0) return PEM_ERR_FORMAT;

    /* Find end tag */
    const char *footer = NULL;
    const char *q = body;
    while (q + end_tag_len <= end) {
        if (memcmp(q, end_tag, (size_t)end_tag_len) == 0) { footer = q; break; }
        q++;
    }
    if (!footer) return PEM_ERR_FORMAT;

    /* Collect base64 content between body and footer, skipping whitespace */
    /* Use der_out as intermediate scratch only if large enough; otherwise fail */
    /* To avoid heap alloc, we write base64 into a local VLA or fixed buffer.
     * PEM bodies are typically ≤16 KB, so 24 KB stack is fine for most keys. */
    char b64buf[24576];
    size_t b64len = 0;
    for (const char *r = body; r < footer; r++) {
        unsigned char c = (unsigned char)*r;
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        if (b64len >= sizeof(b64buf)) return PEM_ERR_BUFFER;
        b64buf[b64len++] = (char)c;
    }

    size_t decoded = 0;
    int rc = radix_base64_decode(b64buf, b64len, der_out, der_cap, &decoded);
    if (rc != 0) return PEM_ERR_BASE64;

    *der_len = decoded;
    return PEM_OK;
}
