#ifndef NEXTSSL_COMMON_UDBF_H
#define NEXTSSL_COMMON_UDBF_H

#include <stddef.h>
#include <stdint.h>

/*
 * UDBF — User Defined Buffer Function
 *
 * Provides a deterministic byte-feeder for key generation testing and
 * known-answer tests.  The caller feeds raw seed bytes once; subsequent
 * udbf_read() calls derive domain-separated material via HKDF labels.
 *
 * Security contract:
 *   - udbf_read() returns UDBF_ERR_EXHAUSTED if remaining bytes are
 *     insufficient.  It NEVER zero-fills.  Callers must handle the error.
 *   - In production mode UDBF must be disabled.  Enable only for testing
 *     or deterministic-keygen flows where the caller guarantees entropy.
 *   - Call udbf_wipe() when done to erase the internal state.
 */

typedef enum {
    UDBF_OK            =  0,
    UDBF_ERR_NULL      = -1, /* null or zero-length input rejected             */
    UDBF_ERR_EXHAUSTED = -2, /* insufficient bytes remaining for the request   */
    UDBF_ERR_DISABLED  = -3, /* UDBF is not currently active                  */
    UDBF_ERR_TOO_LARGE = -4, /* feed length exceeds UDBF_MAX_FEED_LEN         */
} udbf_result_t;

#define UDBF_MAX_FEED_LEN  (1u << 20)  /* 1 MB hard ceiling for feed buffer    */
#define UDBF_MIN_FEED_LEN  32u          /* minimum meaningful feed              */

/*
 * udbf_feed - Load root deterministic bytes into UDBF state.
 *
 * Must be called before any udbf_read().  Calling again resets the state.
 *
 * @data: Pointer to seed bytes.
 * @len:  Byte count (UDBF_MIN_FEED_LEN .. UDBF_MAX_FEED_LEN inclusive).
 * @return: UDBF_OK, or UDBF_ERR_NULL / UDBF_ERR_TOO_LARGE.
 */
udbf_result_t udbf_feed(const uint8_t *data, size_t len);

/*
 * udbf_read - Consume bytes for a labelled key operation.
 *
 * Uses HKDF with @label as the `info` field to provide domain separation.
 * If the internal feeder does not have enough bytes remaining, returns
 * UDBF_ERR_EXHAUSTED without writing anything to @out.
 *
 * @label:   Non-NULL, non-empty ASCII string identifying the use-case
 *           (e.g. "mlkem512-keypair", "mldsa44-sign-derand").
 * @out:     Output buffer.
 * @out_len: Number of bytes required.
 * @return:  UDBF_OK, UDBF_ERR_DISABLED, UDBF_ERR_EXHAUSTED, or UDBF_ERR_NULL.
 */
udbf_result_t udbf_read(const char *label, uint8_t *out, size_t out_len);

/*
 * udbf_wipe - Securely erase and disable the UDBF state.
 *
 * Should be called after key generation is complete.  After this call,
 * udbf_read() returns UDBF_ERR_DISABLED until the next udbf_feed().
 */
void udbf_wipe(void);

/*
 * udbf_is_active - Query whether UDBF mode is currently active.
 * @return: 1 if active, 0 if disabled.
 */
int udbf_is_active(void);

/* =========================================================================
 * Per-instance UDBF context
 *
 * Allows multiple independent UDBF streams simultaneously (e.g. user_a and
 * user_b each with their own entropy buffer).  The state lives entirely
 * inside the caller-allocated udbf_ctx_t — no global buffer is touched.
 * ====================================================================== */

typedef struct {
    uint8_t buf[UDBF_MAX_FEED_LEN];
    size_t  buf_len;
    size_t  buf_pos;
    int     enabled;
} udbf_ctx_t;

/*
 * udbf_ctx_feed - Load entropy into a per-instance context.
 * Equivalent to udbf_feed() but writes to ctx, not the global state.
 */
udbf_result_t udbf_ctx_feed(udbf_ctx_t *ctx, const uint8_t *data, size_t len);

/*
 * udbf_ctx_read - Consume domain-separated bytes from a per-instance context.
 * Equivalent to udbf_read() but reads from ctx, not the global state.
 */
udbf_result_t udbf_ctx_read(udbf_ctx_t *ctx, const char *label,
                             uint8_t *out, size_t out_len);

/*
 * udbf_ctx_wipe - Securely erase a per-instance context.
 */
void udbf_ctx_wipe(udbf_ctx_t *ctx);

#endif /* NEXTSSL_COMMON_UDBF_H */
