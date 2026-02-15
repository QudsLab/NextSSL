#include "calc_interface.h"

// Constants for cost estimation (calibrated for a reference CPU)
// Cost unit: 1 elementary op (approx 1 cycle or small block op)

// Argon2: Cost is dominated by memory filling
// 1KB block = 1024 bytes. Argon2 iterates over blocks.
// Cost ≈ t_cost * m_cost_kb * 1024 * OPS_PER_BYTE
#define COST_ARGON2_PER_KB_ITER  1000.0 // Arbitrary calibrated unit

double pow_calc_cost_argon2(const PoWComplexityArgs *args) {
    if (!args) return 0.0;
    
    double ops = (double)args->t_cost * (double)args->m_cost_kb * COST_ARGON2_PER_KB_ITER;
    
    // Initial hashing (Blake2b)
    ops += (double)args->input_len * 1.0; 
    
    return ops;
}
