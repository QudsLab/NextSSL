/* base58check.c — Base58Check encoding / decoding
 *
 * Dependencies:
 *   - src/common/encoding/base58.h  (radix_base58_encode / radix_base58_decode)
 *   - src/hash/fast/sha256.h        (sha256_double_hash)
 */
#include "base58check.h"
#include "base58.h"
#include "sha256.h"
#include <string.h>

/* SHA-256 digest length */
#define SHA256_DIGEST_LEN 32u
/* Checksum bytes appended */
#define CHECKSUM_LEN       4u

/* ---- internal helpers ---------------------------------------------------- */

/* Compute 4-byte checksum: first 4 bytes of SHA-256(SHA-256(data)). */
static void compute_checksum(const uint8_t *data, size_t len,
                              uint8_t checksum[CHECKSUM_LEN])
{
    uint8_t dh[SHA256_DIGEST_LEN];
    sha256_double_hash(data, len, dh);
    memcpy(checksum, dh, CHECKSUM_LEN);
}

/* ---- public API ---------------------------------------------------------- */

int base58check_encode(uint8_t version,
                       const uint8_t *payload, size_t payload_len,
                       char *dst, size_t dstcap,
                       size_t *out_len)
{
    if (!payload || payload_len == 0) return BASE58CHECK_ERR_INPUT;
    if (!dst || dstcap == 0)          return BASE58CHECK_ERR_BUFFER;
    if (payload_len > BASE58CHECK_MAX_PAYLOAD) return BASE58CHECK_ERR_INPUT;

    /* Build: version (1) || payload (payload_len) || checksum (4) */
    size_t raw_len = 1u + payload_len + CHECKSUM_LEN;
    uint8_t raw[1u + BASE58CHECK_MAX_PAYLOAD + CHECKSUM_LEN];

    raw[0] = version;
    memcpy(raw + 1, payload, payload_len);
    compute_checksum(raw, 1u + payload_len, raw + 1u + payload_len);

    size_t encoded_len = 0;
    int rc = radix_base58_encode(raw, raw_len, dst, dstcap, &encoded_len);
    /* Wipe the local copy — it includes the version byte which is
     * not secret, but defensive hygiene is free here. */
    memset(raw, 0, sizeof(raw));

    if (rc != 0) return BASE58CHECK_ERR_ENCODE;
    if (out_len) *out_len = encoded_len;
    return BASE58CHECK_OK;
}

int base58check_decode(const char *src, size_t srclen,
                       uint8_t *version_out,
                       uint8_t *payload_out, size_t payload_cap,
                       size_t *payload_len)
{
    if (!src || srclen == 0 || !version_out || !payload_out)
        return BASE58CHECK_ERR_INPUT;

    /* Decode the base58 string */
    uint8_t raw[1u + BASE58CHECK_MAX_PAYLOAD + CHECKSUM_LEN];
    size_t  raw_len = 0;
    int rc = radix_base58_decode(src, srclen, raw, sizeof(raw), &raw_len);
    if (rc != 0) return BASE58CHECK_ERR_DECODE;

    /* Must have at least: 1 (version) + 1 (payload) + 4 (checksum) */
    if (raw_len < 1u + 1u + CHECKSUM_LEN) {
        memset(raw, 0, sizeof(raw));
        return BASE58CHECK_ERR_TRUNCATED;
    }

    /* Split: version | body | checksum */
    size_t body_len = raw_len - 1u - CHECKSUM_LEN;

    /* Verify checksum */
    uint8_t expected[CHECKSUM_LEN];
    compute_checksum(raw, 1u + body_len, expected);
    int cs_ok = (memcmp(raw + 1u + body_len, expected, CHECKSUM_LEN) == 0);
    memset(raw + 1u + body_len, 0, CHECKSUM_LEN); /* wipe checksum bytes */

    if (!cs_ok) {
        memset(raw, 0, sizeof(raw));
        return BASE58CHECK_ERR_CHECKSUM;
    }

    if (body_len > payload_cap) {
        memset(raw, 0, sizeof(raw));
        return BASE58CHECK_ERR_BUFFER;
    }

    *version_out = raw[0];
    memcpy(payload_out, raw + 1, body_len);
    memset(raw, 0, sizeof(raw));

    if (payload_len) *payload_len = body_len;
    return BASE58CHECK_OK;
}
