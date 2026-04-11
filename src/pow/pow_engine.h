/* pow_engine.h — Dynamic PoW hashing engine.
 *
 * All 46 algorithms are registered in a single dispatch table in pow_engine.c.
 * No per-algorithm .c files — engine delegates to src/hash/adapters/ directly.
 */
#ifndef POW_ENGINE_H
#define POW_ENGINE_H

#include <stdint.h>
#include <stddef.h>
#include "pow_config.h"

/* Hash input with the algorithm named in cfg->algo.
 * For KDF/XOF algorithms, cfg->kdf supplies tuning params
 * (zero-initialised = use built-in defaults).
 * out must be large enough for the algorithm's digest (use pow_engine_digest_size).
 * Returns 0 on success, -1 on bad args / unknown algo / adapter failure. */
int pow_engine_hash(const uint8_t    *in,
                    size_t            len,
                    const pow_config_t *cfg,
                    uint8_t          *out);

/* Return the digest size in bytes for cfg->algo, or 0 on unknown algo. */
size_t pow_engine_digest_size(const pow_config_t *cfg);

/* Returns 1 if name is a registered algorithm, 0 otherwise. */
int pow_engine_algo_valid(const char *name);

#endif /* POW_ENGINE_H */
