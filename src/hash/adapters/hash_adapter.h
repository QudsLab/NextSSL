/* hash_adapter.h — Per-instance hash adapter with configurable state (Plan 40002)
 *
 * hash_adapter_t is the generic handle for any hash algorithm instance.
 * Unlike hash_ops_t (which is a shared, stateless vtable), a hash_adapter_t
 * owns its own heap-allocated state (impl) and carries per-instance
 * configuration such as memory cost, work factor, and salt.
 *
 * Lifecycle:
 *   1. Create:   hash_adapter_t *a = sha256_adapter_create();
 *   2. Config:   argon2id_adapter_config(a->impl, 65536, 2, 1, 32, salt, 16);
 *   3. Use:      a->hash_fn(a->impl, data, len, out, out_len);   // one-shot
 *             OR a->init_fn(a->impl);                            // streaming
 *                a->update_fn(a->impl, data, len);
 *                a->final_fn(a->impl, out, out_len);
 *   4. Destroy:  hash_adapter_free(a);
 *
 * Rules:
 *   - hash_fn must NOT call into the seed system (no seed_derive_random).
 *   - init_fn resets internal accumulator state; configuration params persist.
 *   - HMAC / PBKDF2 / HKDF consume hash_adapter_t exclusively (no string names).
 */
#ifndef HASH_ADAPTER_H
#define HASH_ADAPTER_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

/* -------------------------------------------------------------------------
 * hash_adapter_t — generic per-instance adapter for any hash algorithm
 * -------------------------------------------------------------------------*/
typedef struct hash_adapter_s {
    void   *impl;          /* heap-allocated per-instance state */
    size_t  digest_size;   /* hash output length in bytes */
    size_t  block_size;    /* compression block size in bytes (needed by HMAC) */

    /* one-shot hash — returns 0 on success, -1 on error */
    int  (*hash_fn)   (void *impl,
                       const uint8_t *data, size_t data_len,
                       uint8_t *out, size_t out_len);

    /* streaming interface — required for use with HMAC */
    void (*init_fn)   (void *impl);
    void (*update_fn) (void *impl, const uint8_t *data, size_t len);
    void (*final_fn)  (void *impl, uint8_t *out, size_t out_len);

    /* cleanup — frees impl; caller must also free the adapter itself */
    void (*destroy_fn)(void *impl);
} hash_adapter_t;

/* -------------------------------------------------------------------------
 * hash_adapter_free — destroy impl and free the adapter struct itself.
 * Safe to call with NULL.
 * -------------------------------------------------------------------------*/
static inline void hash_adapter_free(hash_adapter_t *a)
{
    if (!a) return;
    if (a->destroy_fn && a->impl) a->destroy_fn(a->impl);
    free(a);
}

#endif /* HASH_ADAPTER_H */
