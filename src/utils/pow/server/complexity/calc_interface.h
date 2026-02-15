#ifndef LEYLINE_POW_CALC_INTERFACE_H
#define LEYLINE_POW_CALC_INTERFACE_H

#include "pow_protocol.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    size_t input_len;
    // Argon2 specific
    uint32_t t_cost;
    uint32_t m_cost_kb;
    uint32_t parallelism;
} PoWComplexityArgs;

/**
 * Returns an abstract "Operation Cost" (approximate elementary ops).
 * This value is used to estimate time complexity.
 */
double pow_calc_cost(PoWAlgorithm algo, const PoWComplexityArgs *args);

#ifdef __cplusplus
}
#endif

#endif // LEYLINE_POW_CALC_INTERFACE_H
