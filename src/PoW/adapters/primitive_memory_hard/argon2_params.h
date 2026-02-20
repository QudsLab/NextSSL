#ifndef ARGON2_PARAMS_H
#define ARGON2_PARAMS_H

#include <stdint.h>

typedef struct {
    uint32_t out_len;       // Output length (bytes)
    uint32_t memory_kib;    // Memory cost (KiB)
    uint32_t iterations;    // Time cost (iterations)
    uint32_t threads;       // Parallelism
} Argon2Params;

#endif // ARGON2_PARAMS_H
