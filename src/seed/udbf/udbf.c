#include "udbf.h"
#include "../../PQCrypto/common/hkdf/hkdf.h"
#include <string.h>

/*
 * UDBF — User Defined Buffer Function implementation.
 *
 * Extracted from src/PQCrypto/common/randombytes.c and fixed:
 *   Old bug: when buffer ran out, remaining bytes were zero-filled silently.
 *   Fix: udbf_read() returns UDBF_ERR_EXHAUSTED without writing anything.
 *
 * Domain separation is provided via HKDF with the label as the `info` field.
 * Each labelled call derives a fresh sub-key from the remaining buffer bytes
 * so that identical seed material fed for different operations yields distinct
 * outputs.
 */

/* Internal state — module-private */
static uint8_t  s_buffer[UDBF_MAX_FEED_LEN];
static size_t   s_buf_len = 0;
static size_t   s_buf_pos = 0;
static int      s_enabled  = 0;

udbf_result_t udbf_feed(const uint8_t *data, size_t len)
{
    if (!data || len == 0)             return UDBF_ERR_NULL;
    if (len < UDBF_MIN_FEED_LEN)      return UDBF_ERR_NULL;   /* too short    */
    if (len > UDBF_MAX_FEED_LEN)      return UDBF_ERR_TOO_LARGE;

    /* Wipe any previous state before loading */
    volatile uint8_t *p = (volatile uint8_t *)s_buffer;
    for (size_t i = 0; i < s_buf_len; i++) p[i] = 0;

    memcpy(s_buffer, data, len);
    s_buf_len = len;
    s_buf_pos = 0;
    s_enabled  = 1;
    return UDBF_OK;
}

udbf_result_t udbf_read(const char *label, uint8_t *out, size_t out_len)
{
    if (!s_enabled)                     return UDBF_ERR_DISABLED;
    if (!label || label[0] == '\0')     return UDBF_ERR_NULL;
    if (!out || out_len == 0)           return UDBF_ERR_NULL;

    size_t remaining = s_buf_len - s_buf_pos;
    if (remaining == 0)                 return UDBF_ERR_EXHAUSTED;

    /*
     * Use HKDF to derive @out_len domain-separated bytes from the next
     * `ikm_len` bytes of s_buffer.  We consume min(remaining, out_len + 32)
     * bytes as IKM so that repeated reads with different labels differ even
     * when the underlying byte run is the same.
     *
     * We need at least out_len bytes of IKM for HKDF to be meaningful.
     */
    size_t ikm_len = remaining < out_len ? remaining : out_len;
    /* Require at least as many IKM bytes as requested output */
    if (ikm_len < out_len)             return UDBF_ERR_EXHAUSTED;

    const uint8_t *ikm = s_buffer + s_buf_pos;
    size_t label_len   = 0;
    while (label[label_len]) label_len++; /* strlen without including <string.h> twice */

    /* HKDF: no salt, IKM from buffer, label as info, output to @out */
    hkdf(NULL, 0,
         ikm,  ikm_len,
         (const uint8_t *)label, label_len,
         out,  out_len);

    s_buf_pos += ikm_len;
    return UDBF_OK;
}

void udbf_wipe(void)
{
    volatile uint8_t *p = (volatile uint8_t *)s_buffer;
    for (size_t i = 0; i < sizeof(s_buffer); i++) p[i] = 0;
    s_buf_len = 0;
    s_buf_pos = 0;
    s_enabled  = 0;
}

int udbf_is_active(void)
{
    return s_enabled;
}

/* =========================================================================
 * Per-instance context API
 * ====================================================================== */

udbf_result_t udbf_ctx_feed(udbf_ctx_t *ctx, const uint8_t *data, size_t len)
{
    if (!ctx)                          return UDBF_ERR_NULL;
    if (!data || len == 0)             return UDBF_ERR_NULL;
    if (len < UDBF_MIN_FEED_LEN)      return UDBF_ERR_NULL;
    if (len > UDBF_MAX_FEED_LEN)      return UDBF_ERR_TOO_LARGE;

    /* Wipe any previous state before loading */
    volatile uint8_t *p = (volatile uint8_t *)ctx->buf;
    for (size_t i = 0; i < ctx->buf_len; i++) p[i] = 0;

    memcpy(ctx->buf, data, len);
    ctx->buf_len = len;
    ctx->buf_pos = 0;
    ctx->enabled = 1;
    return UDBF_OK;
}

udbf_result_t udbf_ctx_read(udbf_ctx_t *ctx, const char *label,
                             uint8_t *out, size_t out_len)
{
    if (!ctx)                           return UDBF_ERR_NULL;
    if (!ctx->enabled)                  return UDBF_ERR_DISABLED;
    if (!label || label[0] == '\0')     return UDBF_ERR_NULL;
    if (!out || out_len == 0)           return UDBF_ERR_NULL;

    size_t remaining = ctx->buf_len - ctx->buf_pos;
    if (remaining == 0)                 return UDBF_ERR_EXHAUSTED;

    size_t ikm_len = remaining < out_len ? remaining : out_len;
    if (ikm_len < out_len)             return UDBF_ERR_EXHAUSTED;

    const uint8_t *ikm = ctx->buf + ctx->buf_pos;
    size_t label_len   = 0;
    while (label[label_len]) label_len++;

    hkdf(NULL, 0,
         ikm,  ikm_len,
         (const uint8_t *)label, label_len,
         out,  out_len);

    ctx->buf_pos += ikm_len;
    return UDBF_OK;
}

void udbf_ctx_wipe(udbf_ctx_t *ctx)
{
    if (!ctx) return;
    volatile uint8_t *p = (volatile uint8_t *)ctx->buf;
    for (size_t i = 0; i < sizeof(ctx->buf); i++) p[i] = 0;
    ctx->buf_len = 0;
    ctx->buf_pos = 0;
    ctx->enabled = 0;
}
