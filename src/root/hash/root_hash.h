/* root_hash.h — Exported Hash API (Plan 405)
 *
 * Provides one-shot hash computation and algorithm metadata query over
 * all 41+ algorithms registered in the hash registry.
 */
#ifndef ROOT_HASH_H
#define ROOT_HASH_H

#include <stddef.h>
#include <stdint.h>
#include "../nextssl_export.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------
 * nextssl_hash_compute — Hash a buffer in one call
 * -------------------------------------------------------------------------
 * algo     — canonical algorithm name: "sha256", "blake3", "sha3-256", etc.
 * data     — input bytes (may be NULL if data_len == 0)
 * data_len — length of input
 * out      — caller-allocated output buffer; must be >= *out_len bytes
 * out_len  — IN: capacity of out; OUT: bytes written (digest size)
 *
 * Returns 0 on success, -1 on error (unknown algo, NULL out, capacity too small).
 */
NEXTSSL_API int nextssl_hash_compute(
    const char    *algo,
    const uint8_t *data,
    size_t         data_len,
    uint8_t       *out,
    size_t        *out_len);

/* -------------------------------------------------------------------------
 * nextssl_hash_digest_size — Return digest size in bytes for named algorithm
 * Returns 0 if algorithm is not registered.
 */
NEXTSSL_API size_t nextssl_hash_digest_size(const char *algo);

/* -------------------------------------------------------------------------
 * nextssl_hash_block_size — Return block size in bytes for named algorithm
 * Returns 0 if algorithm is not registered.
 */
NEXTSSL_API size_t nextssl_hash_block_size(const char *algo);

/* -------------------------------------------------------------------------
 * nextssl_hash_list — Return NULL-terminated array of registered algo names
 * The returned pointer is to a static string array; do not free or modify it.
 */
NEXTSSL_API const char **nextssl_hash_list(void);

#ifdef __cplusplus
}
#endif

#endif /* ROOT_HASH_H */
