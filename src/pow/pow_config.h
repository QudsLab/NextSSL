/* pow_config.h — Algorithm + KDF configuration for the PoW engine.
 *
 * pow_config_t  — passed to pow_engine_hash() to select the algorithm
 *                 and supply KDF/XOF tuning parameters.
 * pow_kdf_params_t — all per-algorithm tunable knobs in one flat struct.
 *                    Zero-initialised → engine uses built-in defaults.
 */
#ifndef POW_CONFIG_H
#define POW_CONFIG_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t m_kib;        /* argon2:      memory KiB          (default 65536) */
    uint32_t t;            /* argon2:      passes              (default 2)     */
    uint32_t p;            /* argon2:      lanes               (default 1)     */
    uint64_t scrypt_N;     /* scrypt/yes:  cost factor         (default 16384) */
    uint32_t scrypt_r;     /* scrypt/yes:  block multiplier    (default 8)     */
    uint32_t scrypt_p;     /* scrypt/yes:  parallelism         (default 1)     */
    uint8_t  garlic;       /* catena:      log2 memory         (default 14)    */
    uint8_t  lambda;       /* catena:      passes              (default 2)     */
    uint64_t t_cost;       /* lyra2:       time cost           (default 1)     */
    uint32_t nrows;        /* lyra2:       matrix rows         (default 8)     */
    uint32_t ncols;        /* lyra2:       matrix cols         (default 256)   */
    uint32_t work_factor;  /* bcrypt/makwa:cost / log2-iter    (default 10)    */
    uint32_t modulus_bits; /* makwa:       modulus size        (default 2048)  */
    uint32_t s_cost;       /* balloon:     space KiB           (default 1024)  */
    uint32_t balloon_t;    /* balloon:     time cost           (default 3)     */
    uint32_t threads;      /* balloon:     threads             (default 1)     */
    uint32_t pomelo_t;     /* pomelo:      log2 sweeps         (default 1)     */
    uint32_t pomelo_m;     /* pomelo:      log2 KiB            (default 14)    */
    uint32_t output_size;  /* XOF:         squeeze bytes       (default 32)    */
    const uint8_t *salt;   /* deterministic salt (NULL = adapter chooses)     */
    size_t   salt_len;
} pow_kdf_params_t;

typedef struct {
    const char       *algo; /* canonical algo name e.g. "sha256", "argon2id" */
    pow_kdf_params_t  kdf;  /* ignored for plain hashes (config_fn == NULL)  */
} pow_config_t;

#endif /* POW_CONFIG_H */
