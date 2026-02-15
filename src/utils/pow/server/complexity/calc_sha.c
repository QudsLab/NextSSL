#include "calc_interface.h"

// SHA256: Block size 64 bytes
// Cost ≈ (Input / 64) * OPS_PER_BLOCK
#define COST_SHA256_BLOCK 500.0
#define COST_MD5_BLOCK    200.0
#define COST_SHA1_BLOCK   300.0

double pow_calc_cost_sha(PoWAlgorithm algo, const PoWComplexityArgs *args) {
    if (!args) return 0.0;
    
    double block_cost = COST_SHA256_BLOCK;
    size_t block_size = 64;
    
    if (algo == POW_ALGO_MD5) {
        block_cost = COST_MD5_BLOCK;
    } else if (algo == POW_ALGO_SHA1) {
        block_cost = COST_SHA1_BLOCK;
    }
    
    size_t num_blocks = (args->input_len + 8 + 64) / block_size; // Rough padding estimate
    return (double)num_blocks * block_cost;
}
